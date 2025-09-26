<#
.SYNOPSIS
  Parses Windows boot time strings into DateTime objects and calculates uptime in days.
.DESCRIPTION
  Accepts boot time strings from tools such as systeminfo, attempts to interpret WMI and culture-specific formats, and
  reports the parsed boot time alongside the estimated uptime.
.PARAMETER BootString
  Provides the boot time string to parse. When omitted, the script queries systeminfo for the most recent value.
.EXAMPLE
  PS C:\> .\Test-UptimeParse.ps1

  Retrieves the boot string from systeminfo, parses it, and prints the approximate uptime.
.EXAMPLE
  PS C:\> .\Test-UptimeParse.ps1 -BootString '20240101120000.000000-300'

  Parses the supplied WMI-formatted timestamp and reports the uptime.
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
