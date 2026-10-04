$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path $PSScriptRoot -Parent
$upstreamPath = Join-Path $projectRoot 'upstream/unshield'
if (!(Test-Path -LiteralPath $upstreamPath)) {
    git clone https://github.com/twogood/unshield.git $upstreamPath
    if ($LASTEXITCODE) { throw 'Upstream clone failed' }
}
git -C $upstreamPath checkout --detach cbed3d19ef9cdf4e5fb86b9d65e48f1bf8d539db
if ($LASTEXITCODE) { throw 'Could not select pinned upstream revision' }
