<#!
.SYNOPSIS
    Flags adapters with DHCP disabled but lacking static gateway or DNS configuration.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$InputFolder
)

$repoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
Import-Module (Join-Path -Path $repoRoot -ChildPath 'Modules/Common.psm1') -Force
. (Join-Path -Path $PSScriptRoot -ChildPath 'Dhcp-AnalyzerCommon.ps1')

$payload = Get-DhcpCollectorPayload -InputFolder $InputFolder -FileName 'dhcp-static-configuration.json'
$ads = Ensure-Array $payload.AdapterConfigurations; Write-Host ("DBG DHCP PAYLOAD: adapters={0} dhcpEnabled={1} gateway={2} dns0={3}" -f $ads.Count,($ads | Select-Object -First 1 -ExpandProperty DHCPEnabled),($ads | Select-Object -First 1 -ExpandProperty DefaultIPGateway | Select-Object -First 1),($ads | Select-Object -First 1 -ExpandProperty DNSServerSearchOrder | Select-Object -First 1))
if ($null -eq $payload) { return @() }
if ($payload.PSObject.Properties['Error']) {
    return @(New-DhcpFinding -Check 'DHCP disabled without static config' -Severity 'warning' -Message "Unable to parse DHCP static configuration collector output." -Evidence ([ordered]@{ Error = $payload.Error; File = $payload.File }))
}

$findings = @()
foreach ($adapter in (Ensure-Array $payload.AdapterConfigurations)) {
    if (-not $adapter) { continue }

    $dhcpEnabled = ConvertTo-NullableBool $adapter.DHCPEnabled
    if ($dhcpEnabled -ne $false) { continue }

    $gateways = Ensure-Array $adapter.DefaultIPGateway
    $dnsServers = Ensure-Array $adapter.DNSServerSearchOrder
    $hasGateway = $gateways | Where-Object { $_ -and $_.Trim() }
    $hasDns = $dnsServers | Where-Object { $_ -and $_.Trim() }

    if (-not $hasGateway -and -not $hasDns) {
        $findings += New-DhcpFinding -Check 'DHCP disabled without static config' -Severity 'high' -Message "Adapter $(Get-AdapterIdentity $adapter) has DHCP disabled but no static gateway or DNS servers configured." -Evidence ([ordered]@{
            Adapter    = Get-AdapterIdentity $adapter
            Gateways   = Format-StringList $gateways
            DnsServers = Format-StringList $dnsServers
            IPAddress  = Format-StringList (Get-AdapterIpv4Addresses $adapter)
        })
    }
}

return $findings
