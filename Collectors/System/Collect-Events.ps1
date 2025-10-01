<#!
.SYNOPSIS
    Collects recent Application and System event log entries.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\\CollectorCommon.ps1')

function Get-RecentEvents {
    param(
        [Parameter(Mandatory)]
        [string]$LogName,

        [int]$MaxEvents = 100
    )

    try {
        return Get-WinEvent -LogName $LogName -MaxEvents $MaxEvents -ErrorAction Stop | Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message
    } catch {
        return [PSCustomObject]@{
            LogName = $LogName
            Error   = $_.Exception.Message
        }
    }
}

function Get-FilteredEvents {
    param(
        [Parameter(Mandatory)]
        [string]$LogName,

        [int[]]$EventIds,

        [datetime]$StartTime,

        [string]$ProviderName
    )

    $metadata = [ordered]@{
        LogName = $LogName
    }

    if ($PSBoundParameters.ContainsKey('EventIds') -and $EventIds) {
        $metadata['EventIds'] = @($EventIds)
    }

    if ($PSBoundParameters.ContainsKey('ProviderName') -and $ProviderName) {
        $metadata['Provider'] = $ProviderName
    }

    if ($PSBoundParameters.ContainsKey('StartTime') -and $StartTime) {
        $metadata['WindowStartUtc'] = $StartTime.ToUniversalTime().ToString('o')
    }

    try {
        $filter = @{ LogName = $LogName }

        if ($PSBoundParameters.ContainsKey('EventIds') -and $EventIds) {
            $filter['Id'] = $EventIds
        }

        if ($PSBoundParameters.ContainsKey('StartTime') -and $StartTime) {
            $filter['StartTime'] = $StartTime
        }

        if ($PSBoundParameters.ContainsKey('ProviderName') -and $ProviderName) {
            $filter['ProviderName'] = $ProviderName
        }

        $events = @(
            Get-WinEvent -FilterHashtable $filter -ErrorAction Stop |
                Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message
        )

        $metadata['Entries'] = $events
    } catch {
        $metadata['Error'] = $_.Exception.Message
    }

    return [PSCustomObject]$metadata
}

function Invoke-Main {
    $windowStart = [DateTime]::UtcNow.AddDays(-7)

    $payload = [ordered]@{
        System      = Get-RecentEvents -LogName 'System'
        Application = Get-RecentEvents -LogName 'Application'
        GroupPolicy = Get-RecentEvents -LogName 'Microsoft-Windows-GroupPolicy/Operational' -MaxEvents 200
        Vpn         = [ordered]@{
            WindowDays     = 7
            WindowStartUtc = $windowStart.ToString('o')
            RasClient      = Get-FilteredEvents -LogName 'Microsoft-Windows-RasClient/Operational' -EventIds @(20227, 20226) -StartTime $windowStart
            IkeOperational = Get-FilteredEvents -LogName 'Microsoft-Windows-IKE/Operational' -EventIds @(4653, 4654) -StartTime $windowStart
            IkeSystem      = Get-FilteredEvents -LogName 'System' -EventIds @(4653, 4654) -StartTime $windowStart -ProviderName 'Microsoft-Windows-IKEEXT'
        }
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'events.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
