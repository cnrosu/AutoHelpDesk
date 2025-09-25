<#!
.SYNOPSIS
    Highlights DHCP leases that appear stale compared to their expected renewal window.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$InputFolder
)

$repoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
Import-Module (Join-Path -Path $repoRoot -ChildPath 'Modules/Common.psm1') -Force
. (Join-Path -Path $PSScriptRoot -ChildPath 'Dhcp-AnalyzerCommon.ps1')

$payload = Get-DhcpCollectorPayload -InputFolder $InputFolder -FileName 'dhcp-stale-leases.json'
if ($null -eq $payload) { return @() }
if ($payload.PSObject.Properties['Error']) {
    return @(New-DhcpFinding -Check 'Stale DHCP leases' -Severity 'warning' -Message "Unable to parse DHCP stale lease collector output." -Evidence ([ordered]@{ Error = $payload.Error; File = $payload.File }))
}

$now = ConvertFrom-Iso8601 $payload.CurrentTime
if (-not $now) { $now = Get-Date }

$findings = @()
foreach ($adapter in (Ensure-Array $payload.AdapterConfigurations)) {
    if (-not $adapter) { continue }
    if (ConvertTo-NullableBool $adapter.DHCPEnabled -ne $true) { continue }

    $obtained = ConvertFrom-Iso8601 $adapter.DHCPLeaseObtained
    if (-not $obtained) { continue }

    $leaseAge = $now - $obtained
    if ($leaseAge.TotalMinutes -le 0) { continue }

    $expires = ConvertFrom-Iso8601 $adapter.DHCPLeaseExpires
    $leaseDuration = $null
    if ($expires) { $leaseDuration = $expires - $obtained }

    $shouldFlag = $false
    $evidence = [ordered]@{
        Adapter       = Get-AdapterIdentity $adapter
        LeaseObtained = $obtained.ToString('o')
        CheckedAt     = $now.ToString('o')
        LeaseAgeDays  = [math]::Round($leaseAge.TotalDays, 2)
    }

    if ($leaseDuration -and $leaseDuration.TotalMinutes -gt 0) {
        $durationMinutes = [math]::Max($leaseDuration.TotalMinutes, 1)
        $multiple = $leaseAge.TotalMinutes / $durationMinutes
        $evidence['LeaseExpires'] = $expires.ToString('o')
        $evidence['LeaseDurationHours'] = [math]::Round($leaseDuration.TotalHours, 2)
        $evidence['RenewalMultiple'] = [math]::Round($multiple, 2)

        if ($leaseAge.TotalDays -ge 7 -and $multiple -ge 10) {
            $shouldFlag = $true
        }
    } elseif ($leaseAge.TotalDays -ge 14) {
        $shouldFlag = $true
    }

    if ($shouldFlag) {
        $message = "DHCP lease for $(Get-AdapterIdentity $adapter) appears stale; obtained $([math]::Round($leaseAge.TotalDays,2)) days ago."
        $findings += New-DhcpFinding -Check 'Stale DHCP leases' -Severity 'medium' -Message $message -Evidence $evidence
    }
}

return $findings
