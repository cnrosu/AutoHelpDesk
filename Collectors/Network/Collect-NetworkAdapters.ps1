<#!
.SYNOPSIS
    Collects network adapter configuration, IP assignments, and operational state.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\\CollectorCommon.ps1')

function Get-AdapterConfigurations {
    try {
        return Get-NetAdapter -ErrorAction Stop | Select-Object Name, InterfaceDescription, Status, LinkSpeed, MacAddress, DriverInformation
    } catch {
        return [PSCustomObject]@{
            Source = 'Get-NetAdapter'
            Error  = $_.Exception.Message
        }
    }
}

function Get-NetIPAssignments {
    try {
        return Get-NetIPConfiguration -ErrorAction Stop | Select-Object InterfaceAlias, InterfaceDescription, IPv4Address, IPv6Address, DNSServer, IPv4DefaultGateway
    } catch {
        return [PSCustomObject]@{
            Source = 'Get-NetIPConfiguration'
            Error  = $_.Exception.Message
        }
    }
}

function Get-NetworkAdapterState {
    try {
        return Get-NetAdapterAdvancedProperty -ErrorAction Stop | Select-Object Name, DisplayName, DisplayValue
    } catch {
        return [PSCustomObject]@{
            Source = 'Get-NetAdapterAdvancedProperty'
            Error  = $_.Exception.Message
        }
    }
}

function Invoke-Main {
    $payload = [ordered]@{
        Adapters   = Get-AdapterConfigurations
        IPConfig   = Get-NetIPAssignments
        Properties = Get-NetworkAdapterState
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'network-adapters.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
