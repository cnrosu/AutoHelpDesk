<#!
.SYNOPSIS
    Collects core network diagnostics including IP configuration, routing table, netstat, and ARP cache.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\\CollectorCommon.ps1')

function Get-IpConfiguration {
    return Invoke-CollectorNativeCommand -FilePath 'ipconfig.exe' -ArgumentList '/all' -SourceLabel 'ipconfig.exe'
}

function Get-RoutingTable {
    return Invoke-CollectorNativeCommand -FilePath 'route.exe' -ArgumentList 'print' -SourceLabel 'route.exe'
}

function Get-NetstatSnapshot {
    return Invoke-CollectorNativeCommand -FilePath 'netstat.exe' -ArgumentList '-ano' -SourceLabel 'netstat.exe'
}

function Get-ArpCache {
    return Invoke-CollectorNativeCommand -FilePath 'arp.exe' -ArgumentList '-a' -SourceLabel 'arp.exe'
}

function Invoke-Main {
    $payload = [ordered]@{
        IpConfig = Get-IpConfiguration
        Route    = Get-RoutingTable
        Netstat  = Get-NetstatSnapshot
        Arp      = Get-ArpCache
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'network.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
