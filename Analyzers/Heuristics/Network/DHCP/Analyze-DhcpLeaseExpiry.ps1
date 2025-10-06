<#!
.SYNOPSIS
    Detects DHCP leases that are expired or near expiration based on local lease timestamps.
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

. (Join-Path -Path $PSScriptRoot -ChildPath 'Dhcp-AnalyzerHelper.ps1')

Write-DhcpDebug -Message 'Analyzing DHCP lease expiry' -Data ([ordered]@{ InputFolder = $InputFolder })

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
    $leaseDuration = $null
    if ($obtained) {
        $leaseDuration = $expires - $obtained
        if ($leaseDuration.TotalSeconds -lt 0) { $leaseDuration = $null }
    }
    $evidence = [ordered]@{
        Adapter        = Get-AdapterIdentity $adapter
        LeaseObtained  = $( if ($obtained) { $obtained.ToString('o') } else { $adapter.DHCPLeaseObtained } )
        LeaseExpires   = $expires.ToString('o')
        CheckedAt      = $now.ToString('o')
    }

    if ($timeRemaining.TotalSeconds -le 0) {
        $findings += New-DhcpFinding -Check 'Expired or near-expiring leases' -Severity 'critical' -Message "DHCP lease for $(Get-AdapterIdentity $adapter) expired at $($expires.ToString('g'))." -Evidence $evidence
        continue
    }

    $minutesRemaining = [math]::Round($timeRemaining.TotalMinutes,2)
    if ($timeRemaining.TotalMinutes -le 30) {
        $findings += New-DhcpFinding -Check 'Expired or near-expiring leases' -Severity 'high' -Message "DHCP lease for $(Get-AdapterIdentity $adapter) expires within $minutesRemaining minutes." -Evidence $evidence
        continue
    }

    if ($leaseDuration -and $leaseDuration.TotalHours -gt 0) {
        $percentRemaining = $timeRemaining.TotalSeconds / $leaseDuration.TotalSeconds
        if ($percentRemaining -le 0.05) {
            $findings += New-DhcpFinding -Check 'Expired or near-expiring leases' -Severity 'high' -Message "DHCP lease for $(Get-AdapterIdentity $adapter) is within 5% of expiry ($minutesRemaining minutes remaining)." -Evidence $evidence
            continue
        }
        if ($percentRemaining -le 0.15) {
            $findings += New-DhcpFinding -Check 'Expired or near-expiring leases' -Severity 'medium' -Message "DHCP lease for $(Get-AdapterIdentity $adapter) is nearing renewal window ($([math]::Round($percentRemaining*100,1))% remaining)." -Evidence $evidence
            continue
        }
    } elseif ($timeRemaining.TotalHours -le 2) {
        $findings += New-DhcpFinding -Check 'Expired or near-expiring leases' -Severity 'medium' -Message "DHCP lease for $(Get-AdapterIdentity $adapter) expires in under two hours ($minutesRemaining minutes)." -Evidence $evidence
    }
}

return $findings
