<#!
.SYNOPSIS
    Highlights DHCP leases that appear stale compared to their expected renewal window.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$InputFolder,

    [Parameter(Mandatory)]
    [pscustomobject]$CategoryResult,

    [Parameter(Mandatory)]
    [pscustomobject]$Context
)

Write-DhcpDebug -Message 'Analyzing DHCP stale leases' -Data ([ordered]@{ InputFolder = $InputFolder })

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

    $severity = $null
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

        if ($multiple -ge 20 -and $leaseAge.TotalDays -ge 14) {
            $severity = 'high'
        } elseif ($multiple -ge 10 -and $leaseAge.TotalDays -ge 7) {
            $severity = 'medium'
        } elseif ($multiple -ge 5 -and $leaseAge.TotalDays -ge 3) {
            $severity = 'low'
        }
    } elseif ($leaseAge.TotalDays -ge 30) {
        $severity = 'high'
    } elseif ($leaseAge.TotalDays -ge 14) {
        $severity = 'medium'
    }

    if ($severity) {
        $message = "DHCP lease for $(Get-AdapterIdentity $adapter) appears stale; obtained $([math]::Round($leaseAge.TotalDays,2)) days ago."
        $findings += New-DhcpFinding -Check 'Stale DHCP leases' -Severity $severity -Message $message -Evidence $evidence
    }
}

return $findings
