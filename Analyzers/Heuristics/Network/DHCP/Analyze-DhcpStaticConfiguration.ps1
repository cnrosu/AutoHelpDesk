<#!
.SYNOPSIS
    Flags adapters with DHCP disabled but lacking static gateway or DNS configuration.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [pscustomobject]$CategoryResult,

    [Parameter(Mandatory)]
    [pscustomobject]$Context
)

. (Join-Path -Path $PSScriptRoot -ChildPath 'Dhcp-AnalyzerHelper.ps1')

$fileName = 'dhcp-static-configuration.json'
Write-DhcpDebug -Message 'Analyzing DHCP static configuration' -Data ([ordered]@{ FileName = $fileName })

$payload = Get-DhcpCollectorPayload -Context $Context -FileName $fileName
if ($null -eq $payload) { return @() }

$ads = if ($payload) { Ensure-Array $payload.AdapterConfigurations } else { @() }
Write-Host ("DBG DHCP PAYLOAD: adapters={0}" -f $ads.Count)
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
if ($payload.PSObject.Properties['Error']) {
    return @(New-DhcpFinding -Check 'DHCP disabled without static config' -Severity 'warning' -Message "Unable to parse DHCP static configuration collector output." -Evidence ([ordered]@{ Error = $payload.Error; File = $payload.File }))
}

$findings = @()
foreach ($adapter in $ads) {
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
