<#  Save as Test-UptimeParse.ps1 (or run directly in a PS session)

    .\Test-UptimeParse.ps1
    .\Test-UptimeParse.ps1 -BootString '20240101120000.000000-300'
    .\Test-UptimeParse.ps1 -BootString '13.05.2024 08:12:44'  # example localized format
#>

param(
    [string]$BootString
)

if (-not $BootString) {
    $BootString = ((systeminfo | Select-String 'System Boot Time' | Select-Object -First 1).Line `
                  -replace '.*?:\s*','').Trim()
    if (-not $BootString) {
        Write-Host "No boot string found from systeminfo; supply -BootString." -ForegroundColor Yellow
        return
    }
}

Write-Host "Boot string: $BootString"

$bootDt = $null
if ($BootString -match '^\d{14}\.\d{6}[-+]\d{3}$') {
    try { $bootDt = [System.Management.ManagementDateTimeConverter]::ToDateTime($BootString) } catch {}
}
if (-not $bootDt) {
    $parsedBoot = $null
    if ([datetime]::TryParse($BootString, [ref]$parsedBoot)) {
        $bootDt = $parsedBoot
    }
}

if ($bootDt) {
    $uptimeDays = (New-TimeSpan -Start $bootDt -End (Get-Date)).TotalDays
    "{0} → parsed as {1:u}; uptime ≈ {2:N1} days" -f $BootString, $bootDt, $uptimeDays
} else {
    "'{0}' → Last boot captured; uptime could not be determined." -f $BootString
}
