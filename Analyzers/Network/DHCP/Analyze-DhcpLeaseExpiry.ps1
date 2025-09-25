<#!
.SYNOPSIS
    Detects DHCP leases that are expired or near expiration based on local lease timestamps.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$InputFolder
)

$repoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
Import-Module (Join-Path -Path $repoRoot -ChildPath 'Modules/Common.psm1') -Force
. (Join-Path -Path $PSScriptRoot -ChildPath 'Dhcp-AnalyzerCommon.ps1')

$payload = Get-DhcpCollectorPayload -InputFolder $InputFolder -FileName 'dhcp-lease-expiry.json'
if ($null -eq $payload) { return @() }
if ($payload.PSObject.Properties['Error']) {
    return @(New-DhcpFinding -Check 'Expired or near-expiring leases' -Severity 'warning' -Message "Unable to parse DHCP lease expiry collector output." -Evidence ([ordered]@{ Error = $payload.Error; File = $payload.File }))
}

$now = ConvertFrom-Iso8601 $payload.CurrentTime
if (-not $now) { $now = Get-Date }

$findings = @()
foreach ($adapter in (Ensure-Array $payload.AdapterConfigurations)) {
    if (-not $adapter) { continue }

    $dhcpEnabled = ConvertTo-NullableBool $adapter.DHCPEnabled
    if ($dhcpEnabled -ne $true) { continue }

    $expires = ConvertFrom-Iso8601 $adapter.DHCPLeaseExpires
    if (-not $expires) { continue }

    $obtained = ConvertFrom-Iso8601 $adapter.DHCPLeaseObtained
    $timeRemaining = $expires - $now
    $evidence = [ordered]@{
        Adapter        = Get-AdapterIdentity $adapter
        LeaseObtained  = if ($obtained) { $obtained.ToString('o') } else { $adapter.DHCPLeaseObtained }
        LeaseExpires   = $expires.ToString('o')
        CheckedAt      = $now.ToString('o')
    }

    if ($timeRemaining.TotalSeconds -le 0) {
        $findings += New-DhcpFinding -Check 'Expired or near-expiring leases' -Severity 'critical' -Message "DHCP lease for $(Get-AdapterIdentity $adapter) expired at $($expires.ToString('g'))." -Evidence $evidence
        continue
    }

    if ($timeRemaining.TotalMinutes -le 30) {
        $findings += New-DhcpFinding -Check 'Expired or near-expiring leases' -Severity 'high' -Message "DHCP lease for $(Get-AdapterIdentity $adapter) expires within $([math]::Round($timeRemaining.TotalMinutes,2)) minutes." -Evidence $evidence
    }
}

return $findings
