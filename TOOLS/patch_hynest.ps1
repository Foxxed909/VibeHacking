param(
    [Parameter(Mandatory=$true)]
    [string]$baseDir
)
$protectedFiles = @("dashboard.html", "billing.html", "settings.html", "index.html", "plans.html", "upgrade.html", "updates.html", "payment.html", "live.html")

$guardScript = @"
<script id="hynest-security-guard">
  (function() {
    const token = localStorage.getItem('hynest_token') || sessionStorage.getItem('hynest_session_token');
    if (!token) {
      const next = encodeURIComponent(window.location.pathname + window.location.search);
      window.location.href = 'login.html?next=' + next;
    }
  })();
</script>
"@

Write-Output "[*] Deploying PowerShell Security Patch..."

foreach ($file in $protectedFiles) {
    $path = Join-Path $baseDir $file
    if (Test-Path $path) {
        $content = Get-Content $path -Raw
        if ($content -notlike "*hynest-security-guard*") {
            # Injecting right at the start of the head
            $newContent = $content -replace '<head>', ("<head>`n" + $guardScript)
            Set-Content -Path $path -Value $newContent -Encoding UTF8
            Write-Output "[🟢 FIXED] $file"
        } else {
            Write-Output "[*] Skipping $file (Already protected)"
        }
    } else {
        Write-Output "[-] Skipping $file (Not found)"
    }
}
Write-Output "`n[+] Hynest Cloud Security Guard Deployment Complete."
