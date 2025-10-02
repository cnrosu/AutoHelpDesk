<#!
.SYNOPSIS
    Flags DHCP servers that fall outside expected private addressing ranges.
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
. (Join-Path -Path $PSScriptRoot -ChildPath '..\Network-BaselineHelper.ps1')

Write-DhcpDebug -Message 'Analyzing DHCP unexpected servers' -Data ([ordered]@{ InputFolder = $InputFolder })

$payload = Get-DhcpCollectorPayload -InputFolder $InputFolder -FileName 'dhcp-unexpected-servers.json'
if ($null -eq $payload) { return @() }
if ($payload.PSObject.Properties['Error']) {
    return @(New-DhcpFinding -Check 'Unexpected DHCP servers' -Severity 'warning' -Message "Unable to parse DHCP unexpected server collector output." -Evidence ([ordered]@{ Error = $payload.Error; File = $payload.File }))
}

function Get-DhcpServerAddresses {
    param([string]$Value)

    if (-not $Value) { return @() }
    $parts = [regex]::Split($Value, '[,;\s]+') | Where-Object { $_ -and $_.Trim() }
    $results = @()
    foreach ($part in $parts) {
        $candidate = $part.Trim()
        if ($candidate -match '^\d+\.\d+\.\d+\.\d+$') {
            $results += $candidate
        }
    }
    return $results
}

$findings = @()
$corporateExpectations = Get-NetworkCorporateExpectations -Context $Context
Write-DhcpDebug -Message 'Resolved corporate baseline for DHCP guest detection' -Data ([ordered]@{
    HasProfile = [bool]$corporateExpectations
    Subnets    = if ($corporateExpectations -and $corporateExpectations.Subnets) { $corporateExpectations.Subnets.Count } else { 0 }
    Gateways   = if ($corporateExpectations -and $corporateExpectations.Gateways) { $corporateExpectations.Gateways.Count } else { 0 }
    Servers    = if ($corporateExpectations -and $corporateExpectations.DhcpServers) { $corporateExpectations.DhcpServers.Count } else { 0 }
})
foreach ($adapter in (Ensure-Array $payload.AdapterConfigurations)) {
    if (-not $adapter) { continue }
    if (ConvertTo-NullableBool $adapter.DHCPEnabled -ne $true) { continue }

    $rawServer = if ($adapter.DHCPServer) { [string]$adapter.DHCPServer } else { '' }
    $servers = Get-DhcpServerAddresses -Value $rawServer
    foreach ($server in $servers) {
        if (-not (Test-IsPrivateIPv4 $server)) {
            $findings += New-DhcpFinding -Check 'Unexpected DHCP servers' -Severity 'medium' -Message "Adapter $(Get-AdapterIdentity $adapter) reports DHCP server $server outside private ranges." -Evidence ([ordered]@{
                Adapter    = Get-AdapterIdentity $adapter
                DhcpServer = $server
                RawValue   = $rawServer
                IPAddress  = Format-StringList (Get-AdapterIpv4Addresses $adapter)
            })
        }
    }

    if ($corporateExpectations) {
        $addresses = Get-AdapterIpv4Addresses $adapter
        $gateways = Ensure-Array $adapter.DefaultIPGateway

        $subnetMismatch = $false
        if ($addresses.Count -gt 0 -and $corporateExpectations.Subnets -and $corporateExpectations.Subnets.Count -gt 0) {
            $matchFound = $false
            foreach ($address in $addresses) {
                if (Test-NetworkBaselineIpv4Match -Address $address -Subnets $corporateExpectations.Subnets) {
                    $matchFound = $true
                    break
                }
            }
            $subnetMismatch = -not $matchFound
        }

        $gatewayMismatch = $false
        if ($gateways.Count -gt 0 -and $corporateExpectations.Gateways -and $corporateExpectations.Gateways.Count -gt 0) {
            $gatewayMismatch = $true
            foreach ($gateway in $gateways) {
                if (Test-NetworkBaselineHostMatch -Candidate $gateway -Expected $corporateExpectations.Gateways) {
                    $gatewayMismatch = $false
                    break
                }
            }
        }

        $serverMismatch = $false
        if ($servers.Count -gt 0 -and $corporateExpectations.DhcpServers -and $corporateExpectations.DhcpServers.Count -gt 0) {
            $serverMismatch = $true
            foreach ($server in $servers) {
                if (Test-NetworkBaselineHostMatch -Candidate $server -Expected $corporateExpectations.DhcpServers) {
                    $serverMismatch = $false
                    break
                }
            }
        }

        if ($corporateExpectations.DhcpServers -and $corporateExpectations.DhcpServers.Count -gt 0 -and $servers.Count -eq 0 -and $rawServer) {
            if (-not (Test-NetworkBaselineHostMatch -Candidate $rawServer -Expected $corporateExpectations.DhcpServers)) {
                $serverMismatch = $true
            }
        }

        if ($subnetMismatch -or $gatewayMismatch -or $serverMismatch) {
            $leaseSummary = if ($addresses.Count -gt 0) { ($addresses -join ', ') } else { 'an unknown IP' }
            $gatewaySummary = if ($gateways.Count -gt 0) { ($gateways -join ', ') } else { 'no listed gateway' }
            $serverSummary = if ($servers.Count -gt 0) { ($servers -join ', ') } elseif ($rawServer) { $rawServer } else { 'an unknown server' }

            $evidence = [ordered]@{
                Adapter              = Get-AdapterIdentity $adapter
                LeaseAddresses       = $leaseSummary
                Gateways             = Format-StringList $gateways
                DhcpServerReported   = if ($servers.Count -gt 0) { ($servers -join ', ') } else { $rawServer }
                ExpectedSubnets      = if ($corporateExpectations.Subnets) { ($corporateExpectations.Subnets | ForEach-Object { $_.Text }) } else { @() }
                ExpectedGateways     = Format-StringList $corporateExpectations.Gateways
                ExpectedDhcpServers  = Format-StringList $corporateExpectations.DhcpServers
                LeaseObtained        = if ($adapter.PSObject.Properties['DHCPLeaseObtained']) { [string]$adapter.DHCPLeaseObtained } else { $null }
                LeaseExpires         = if ($adapter.PSObject.Properties['DHCPLeaseExpires']) { [string]$adapter.DHCPLeaseExpires } else { $null }
            }

            $message = "Adapter {0} leased {1} with gateway {2} from DHCP server {3}, so the device is likely on a guest VLAN without corporate access." -f (Get-AdapterIdentity $adapter), $leaseSummary, $gatewaySummary, $serverSummary

            $findings += New-DhcpFinding -Check 'Guest VLAN placement detected' -Severity 'high' -Message $message -Evidence $evidence
        }
    }
}

return $findings
