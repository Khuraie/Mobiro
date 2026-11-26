$ErrorActionPreference = "Stop"

# Fetches upstream open-source translation components cleanly from source (zero precompiled blobs).
$RootDir = Split-Path -Parent $PSScriptRoot
$TpDir = Join-Path $RootDir "third_party"
New-Item -ItemType Directory -Force -Path $TpDir | Out-Null

function Sync-Repo($Name, $Url, $Branch) {
    $Dest = Join-Path $TpDir $Name
    if (Test-Path (Join-Path $Dest ".git")) {
        Write-Host "[Mobiro] Updating $Name ($Branch)..."
        git -C $Dest fetch --depth 1 origin $Branch
        git -C $Dest checkout FETCH_HEAD
    } else {
        Write-Host "[Mobiro] Cloning $Name ($Branch)..."
        git clone --depth 1 --branch $Branch $Url $Dest
    }
}

Sync-Repo "box64" "https://github.com/ptitSeb/box64.git" "main"
Sync-Repo "dxvk"  "https://github.com/doitsujin/dxvk.git"  "master"
Sync-Repo "mesa"  "https://gitlab.freedesktop.org/mesa/mesa.git" "main"

Write-Host "[Mobiro] Open-source third-party sources ready in $TpDir"
