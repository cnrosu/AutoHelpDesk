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
        return Get-NetAdapter -ErrorAction Stop | Select-Object Name, InterfaceDescription, Status, LinkSpeed, MediaConnectionState, MacAddress, DriverInformation
    } catch {
        return [PSCustomObject]@{
            Source = 'Get-NetAdapter'
            Error  = $_.Exception.Message
        }
    }
}

function Get-NetworkLinkEvents {
    $startTime = (Get-Date).AddHours(-72)
    $systemIds = @(27, 32, 4201, 10400, 10401, 10402, 8021, 8026)

    $result = [ordered]@{
        StartTime      = $startTime
        System         = $null
        MsftNetAdapter = @()
    }

    try {
        $systemFilter = @{ LogName = 'System'; StartTime = $startTime; Id = $systemIds }
        $result.System = Get-WinEvent -FilterHashtable $systemFilter -MaxEvents 200 -ErrorAction Stop | Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message
    } catch {
        $result.System = [PSCustomObject]@{
            Source = 'System'
            Error  = $_.Exception.Message
        }
    }

    $netAdapterLogs = @(
        'Microsoft-Windows-NetworkAdapter/Admin',
        'Microsoft-Windows-NetworkAdapter/Operational'
    )

    foreach ($logName in $netAdapterLogs) {
        try {
            $events = Get-WinEvent -FilterHashtable @{ LogName = $logName; StartTime = $startTime } -MaxEvents 200 -ErrorAction Stop | Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message
            $result.MsftNetAdapter += [PSCustomObject]@{
                LogName = $logName
                Events  = $events
            }
        } catch {
            $result.MsftNetAdapter += [PSCustomObject]@{
                LogName = $logName
                Error   = $_.Exception.Message
            }
        }
    }

    return [PSCustomObject]$result
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
        LinkEvents = Get-NetworkLinkEvents
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'network-adapters.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
