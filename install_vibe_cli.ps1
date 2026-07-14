$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Cli = Join-Path $Root "vb\cli.py"
$ShimDir = Join-Path $env:APPDATA "npm"

if (-not (Test-Path -LiteralPath $Cli)) {
    throw "Cannot find CLI entrypoint: $Cli"
}

if (-not (Test-Path -LiteralPath $ShimDir)) {
    New-Item -ItemType Directory -Path $ShimDir | Out-Null
}

$shim = @"
@echo off
setlocal
python "$Cli" %*
exit /b %ERRORLEVEL%
"@

foreach ($name in @("vibe", "vbh", "vibe-hack")) {
    $path = Join-Path $ShimDir "$name.cmd"
    Set-Content -LiteralPath $path -Value $shim -Encoding ASCII
    Write-Host "[+] Installed $path"
}

$pathParts = $env:PATH -split ";"
if ($pathParts -notcontains $ShimDir) {
    Write-Host "[!] $ShimDir is not in the current PATH for this shell."
    Write-Host "    Add it to PATH or open a new shell if your user PATH already includes it."
}

Write-Host "[+] VibeHacking CLI installed. Try: vibe --help"

