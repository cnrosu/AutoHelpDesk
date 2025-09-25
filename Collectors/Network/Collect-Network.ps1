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
    try {
        return ipconfig.exe /all 2>$null
    } catch {
        return [PSCustomObject]@{
            Source = 'ipconfig.exe'
            Error  = $_.Exception.Message
        }
    }
}

function Get-RoutingTable {
    try {
        return route.exe print 2>$null
    } catch {
        return [PSCustomObject]@{
            Source = 'route.exe'
            Error  = $_.Exception.Message
        }
    }
}

function Get-NetstatSnapshot {
    try {
        return netstat.exe -ano 2>$null
    } catch {
        return [PSCustomObject]@{
            Source = 'netstat.exe'
            Error  = $_.Exception.Message
        }
    }
}

function Get-ArpCache {
    try {
        return arp.exe -a 2>$null
    } catch {
        return [PSCustomObject]@{
            Source = 'arp.exe'
            Error  = $_.Exception.Message
        }
    }
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
