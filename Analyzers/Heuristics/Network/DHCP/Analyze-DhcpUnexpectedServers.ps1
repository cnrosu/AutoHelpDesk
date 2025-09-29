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

Write-DhcpDebug -Message 'Analyzing DHCP unexpected servers' -Data ([ordered]@{ InputFolder = $InputFolder })

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
}

return $findings
