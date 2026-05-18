param(
    [Parameter(Mandatory=$true)]
    [string]$baseUrl,
    [string[]]$targets = @("dashboard.html", "billing.html", "settings.html", "index.html")
)

Write-Output "================================"
Write-Output " CLOUD AUDITOR - PowerShell Mode"
Write-Output "================================"
Write-Output "[*] Auditing: $baseUrl`n"

foreach ($t in $targets) {
    $url = "$($baseUrl.TrimEnd('/'))/$t"
    Write-Output "-> Probing: /$t"
    try {
        $res = Invoke-WebRequest -Uri $url -Method Get -UseBasicParsing -TimeoutSec 3
        if ($res.StatusCode -eq 200) {
            Write-Output "   [CRITICAL] Logic Flaw — /$t accessible without auth (200 OK)"
        }
    } catch {
        $code = $_.Exception.Response.StatusCode
        if ($code -in @(401, 403, 404)) {
            Write-Output "   [PASS] Protected ($code) — leap blocked"
        } else {
            Write-Output "   [WARN] Unusual response on /$t ($code)"
        }
    }
}

Write-Output "`n================================"
Write-Output "[+] Cloud Audit Complete."
