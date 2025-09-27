<#!
.SYNOPSIS
    Collects targeted system events related to bugchecks, power resets, and GPU timeouts.
.DESCRIPTION
    Queries the System event log for BugCheck (1001), Kernel-Power (41), Unexpected shutdown (6008),
    and Display driver TDR (4101) events within a configurable time range. The collector emits the
    events with timestamps and parameter values to support downstream heuristics.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\\output'),

    [Parameter()]
    [ValidateRange(1, 90)]
    [int]$DaysToInclude = 30,

    [Parameter()]
    [ValidateRange(1, 1000)]
    [int]$MaxEvents = 200
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\\CollectorCommon.ps1')

function Get-TargetedSystemEvents {
    param(
        [datetime]$StartTime,
        [int[]]$EventIds,
        [int]$MaxEvents
    )

    try {
        $filter = @{ LogName = 'System'; Id = $EventIds; StartTime = $StartTime }
        $events = Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxEvents -ErrorAction Stop |
            Sort-Object -Property TimeCreated -Descending

        return $events | ForEach-Object {
            $properties = @()
            if ($_.Properties) {
                foreach ($prop in $_.Properties) {
                    $properties += $prop.Value
                }
            }

            [ordered]@{
                TimeCreated      = if ($_.TimeCreated) { $_.TimeCreated.ToString('o') } else { $null }
                Id               = $_.Id
                ProviderName     = $_.ProviderName
                LevelDisplayName = $_.LevelDisplayName
                Message          = $_.Message
                Properties       = $properties
            }
        }
    } catch {
        return [PSCustomObject]@{
            Error = $_.Exception.Message
        }
    }
}

function Invoke-Main {
    $eventIds = @(41, 1001, 6008, 4101)
    $startTime = (Get-Date).AddDays(-1 * [math]::Abs($DaysToInclude))

    $events = Get-TargetedSystemEvents -StartTime $startTime -EventIds $eventIds -MaxEvents $MaxEvents

    $payload = [ordered]@{
        Parameters = [ordered]@{
            EventIds      = $eventIds
            StartTime     = $startTime.ToString('o')
            DaysRequested = $DaysToInclude
            MaxEvents     = $MaxEvents
        }
        Events = $events
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'system-critical-events.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
