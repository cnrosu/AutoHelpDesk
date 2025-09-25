<#!
.SYNOPSIS
    Flags DHCP-enabled adapters that are missing DHCP server assignments.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$InputFolder
)

$repoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
Import-Module (Join-Path -Path $repoRoot -ChildPath 'Modules/Common.psm1') -Force
. (Join-Path -Path $PSScriptRoot -ChildPath 'Dhcp-AnalyzerCommon.ps1')

$payload = Get-DhcpCollectorPayload -InputFolder $InputFolder -FileName 'dhcp-missing-server-details.json'
if ($null -eq $payload) { return @() }
if ($payload.PSObject.Properties['Error']) {
    return @(New-DhcpFinding -Check 'Missing DHCP server details' -Severity 'warning' -Message "Unable to parse DHCP missing server collector output." -Evidence ([ordered]@{ Error = $payload.Error; File = $payload.File }))
}

$adapters = Ensure-Array $payload.AdapterConfigurations
$findings = @()
foreach ($adapter in $adapters) {
    if (-not $adapter) { continue }

    $dhcpEnabled = ConvertTo-NullableBool $adapter.DHCPEnabled
    if ($dhcpEnabled -ne $true) { continue }

    $server = ''
    if ($adapter.DHCPServer) { $server = ([string]$adapter.DHCPServer).Trim() }
    if (-not $server -or $server -eq '0.0.0.0' -or $server -eq '::' -or $server -eq '0:0:0:0:0:0:0:0') {
        $findings += New-DhcpFinding -Check 'Missing DHCP server details' -Severity 'high' -Message "Adapter $(Get-AdapterIdentity $adapter) has DHCP enabled but no responding DHCP server." -Evidence ([ordered]@{
            Adapter     = Get-AdapterIdentity $adapter
            DHCPServer  = $server
            IPAddresses = (Format-StringList (Get-AdapterIpv4Addresses $adapter))
            Ipconfig    = Get-TopLines -Text $payload.IpconfigText -Count 50
        })
    }
}

return $findings
