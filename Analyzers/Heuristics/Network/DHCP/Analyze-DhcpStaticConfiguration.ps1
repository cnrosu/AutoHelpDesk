<#!
.SYNOPSIS
    Flags adapters with DHCP disabled but lacking static gateway or DNS configuration.
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

Write-DhcpDebug -Message 'Analyzing DHCP static configuration' -Data ([ordered]@{ InputFolder = $InputFolder })

try {
    $repoRoot = (Resolve-Path -LiteralPath (Join-Path -Path $PSScriptRoot -ChildPath '..\\..\\..\\..')).ProviderPath
} catch {
    $repoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)))
}
$commonModulePath = if ($repoRoot) { Join-Path -Path $repoRoot -ChildPath 'Modules/Common.psm1' } else { $null }
if ($commonModulePath -and (Test-Path -LiteralPath $commonModulePath)) {
    Import-Module $commonModulePath -Force
}
. (Join-Path -Path $PSScriptRoot -ChildPath 'Dhcp-AnalyzerCommon.ps1')

$payload = Get-DhcpCollectorPayload -InputFolder $InputFolder -FileName 'dhcp-static-configuration.json'
$ads = Ensure-Array $payload.AdapterConfigurations
$firstAdapter = $ads | Select-Object -First 1
$dhcpEnabled = if ($firstAdapter -and $firstAdapter.PSObject.Properties['DHCPEnabled']) { $firstAdapter.DHCPEnabled } else { 'n/a' }
$gateway = if ($firstAdapter -and $firstAdapter.PSObject.Properties['DefaultIPGateway']) { ($firstAdapter.DefaultIPGateway | Select-Object -First 1) } else { 'n/a' }
$dns0 = if ($firstAdapter -and $firstAdapter.PSObject.Properties['DNSServerSearchOrder']) { ($firstAdapter.DNSServerSearchOrder | Select-Object -First 1) } else { 'n/a' }
Write-DhcpDebug -Message 'DHCP static configuration payload resolved' -Data ([ordered]@{
    AdapterCount = $ads.Count
    DhcpEnabled  = $dhcpEnabled
    Gateway      = $gateway
    DnsServer    = $dns0
})
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
