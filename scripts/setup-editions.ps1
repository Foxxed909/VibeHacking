<#
  setup-editions.ps1 — set up VibeHacking as two side-by-side folders you can use
  at the same time, from one clone (`main` is a separate, squashed history):

    external\   -> the public edition   (main branch,     ~44 tools)
    internal\   -> the full edition     (internal branch, ~63 tools = all + arsenal)

  Usage (run in an empty folder where you want the two editions to live):
    .\setup-editions.ps1
    .\setup-editions.ps1 git@github.com:Foxxed909/VibeHacking.git    # custom remote/SSH

  Update later:  git -C internal pull   (full edition)
                 git -C external pull    (public edition)
#>
param(
  [string]$Repo = "https://github.com/Foxxed909/VibeHacking.git"
)
$ErrorActionPreference = "Stop"

if ((Test-Path internal) -or (Test-Path external)) {
  Write-Host "[-] An 'internal' or 'external' folder already exists here. Run this in an empty directory." -ForegroundColor Red
  exit 1
}

Write-Host "[*] Cloning $Repo into .\internal (full edition) ..." -ForegroundColor Cyan
git clone $Repo internal
git -C internal switch internal

Write-Host "[*] Adding .\external as a linked worktree on main (public edition) ..." -ForegroundColor Cyan
git -C internal worktree add ..\external main

Write-Host ""
Write-Host "[+] Done. Two live editions from one clone (separate histories):" -ForegroundColor Green
Write-Host "    external\   ->  public edition   (git branch: main)"
Write-Host "    internal\   ->  full edition     (git branch: internal)"
Write-Host ""
Write-Host "Use everything from .\internal :"
Write-Host "    cd internal"
Write-Host "    python vibe.py list"
Write-Host "    python vibe.py scan http://127.0.0.1:3456/"
Write-Host "    python TOOLS\redteam.py --url http://127.0.0.1:8800/"
Write-Host ""
Write-Host "Update later:  git -C internal pull   ;   git -C external pull"
