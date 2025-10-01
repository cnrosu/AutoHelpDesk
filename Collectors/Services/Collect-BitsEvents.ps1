<#!
.SYNOPSIS
    Collects Background Intelligent Transfer Service (BITS) operational events for transfer failure diagnostics.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\CollectorCommon.ps1')

function Get-BitsEventWindow {
    param(
        [int]$HistoryDays = 14
    )

    $now = Get-Date
    $days = if ($HistoryDays -lt 2) { 2 } elseif ($HistoryDays -gt 30) { 30 } else { $HistoryDays }
    $start = $now.AddDays(-1 * $days)

    return [pscustomobject]@{
        Start = $start
        End   = $now
        Days  = $days
    }
}

function Get-BitsClientEvents {
    param(
        [datetime]$StartTime,
        [datetime]$EndTime,
        [int[]]$EventIds
    )

    try {
        $filter = @{ LogName = 'Microsoft-Windows-Bits-Client/Operational' }
        if ($StartTime) { $filter['StartTime'] = $StartTime }
        if ($EndTime)   { $filter['EndTime']   = $EndTime }
        if ($EventIds -and $EventIds.Count -gt 0) { $filter['Id'] = $EventIds }

        $events = Get-WinEvent -FilterHashtable $filter -ErrorAction Stop
    } catch {
        return [pscustomobject]@{
            LogName = 'Microsoft-Windows-Bits-Client/Operational'
            Source  = 'Get-WinEvent'
            Error   = $_.Exception.Message
        }
    }

    $results = [System.Collections.Generic.List[pscustomobject]]::new()
    foreach ($event in $events) {
        $timeCreated = $null
        if ($event.TimeCreated) {
            try {
                $timeCreated = $event.TimeCreated.ToUniversalTime().ToString('o')
            } catch {
                $timeCreated = $event.TimeCreated.ToString()
            }
        }

        $results.Add([pscustomobject]@{
            Id              = $event.Id
            LevelDisplayName= $event.LevelDisplayName
            TaskDisplayName = $event.TaskDisplayName
            ProviderName    = $event.ProviderName
            RecordId        = $event.RecordId
            TimeCreated     = $timeCreated
            Message         = if ($event.Message) { $event.Message.TrimEnd() } else { $null }
        }) | Out-Null
    }

    return $results.ToArray()
}

function Invoke-Main {
    $eventWindow = Get-BitsEventWindow -HistoryDays 14
    $eventIds = 16384..16406

    $events = Get-BitsClientEvents -StartTime $eventWindow.Start -EndTime $eventWindow.End -EventIds $eventIds

    $payload = [ordered]@{
        CurrentTime        = $eventWindow.End.ToUniversalTime().ToString('o')
        WindowStart        = $eventWindow.Start.ToUniversalTime().ToString('o')
        WindowEnd          = $eventWindow.End.ToUniversalTime().ToString('o')
        QueryWindowDays    = $eventWindow.Days
        EventIdRange       = [ordered]@{ Minimum = 16384; Maximum = 16406 }
        EventIdsQueried    = $eventIds
        Events             = $events
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'bits-events.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
