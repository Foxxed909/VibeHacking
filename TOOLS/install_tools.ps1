$targetDir = $PSScriptRoot

# 1. Update User PATH so tools can be run globally without typing 'python'
$oldPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($oldPath -notlike "*$targetDir*") {
    $newPath = $oldPath + ";$targetDir"
    [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
    Write-Output "[+] Added $targetDir to User PATH."
} else {
    Write-Output "[*] $targetDir is already in User PATH."
}

# 2. Create .bat wrappers for each python script
Get-ChildItem -Path $targetDir -Filter *.py | ForEach-Object {
    $baseName = $_.BaseName
    
    # Handle the special cases with dashes
    if ($baseName -eq "random_roll") { $baseName = "random-roll" }
    elseif ($baseName -eq "run_lmx") { $baseName = "run-lmx" }
    
    $batContent = "@echo off`r`npython `"%~dp0\$($_.Name)`" %*`r`npause"
    $batPath = Join-Path -Path $targetDir -ChildPath "$baseName.bat"
    
    # Only create if it doesn't already exist or if we want to force
    Set-Content -Path $batPath -Value $batContent
    Write-Output "[+] Created wrapper: $baseName.bat -> $($_.Name)"
}

Write-Output ""
Write-Output "[!] Installation complete. Restart your terminal (or open a new tab) to use the new global commands."
Write-Output "[!] You can now type 'axios' or 'void' anywhere in your system."
