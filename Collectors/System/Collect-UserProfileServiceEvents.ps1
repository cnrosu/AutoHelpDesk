<#!
.SYNOPSIS
    Collects recent Microsoft-Windows-User Profile Service operational events for profile unload conflicts.
.DESCRIPTION
    Gathers event ID 1530 and 1533 entries from the User Profile Service operational log. A 14-day
    lookback is collected to support heuristics that evaluate both 7-day and 14-day windows.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\\CollectorCommon.ps1')

function Get-UserProfileServiceEvents {
    param(
        [int]$LookbackDays = 14,
        [int]$MaxEvents = 400
    )

    $windowStart = (Get-Date).AddDays(-[math]::Abs($LookbackDays))
    $filter = @{
        LogName   = 'Microsoft-Windows-User Profile Service/Operational'
        Id        = @(1530, 1533)
        StartTime = $windowStart
    }

    try {
        $events = Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxEvents -ErrorAction Stop
    } catch {
        return @([pscustomobject]@{
            Source = 'Get-WinEvent Microsoft-Windows-User Profile Service/Operational'
            Error  = $_.Exception.Message
        })
    }

    $results = [System.Collections.Generic.List[pscustomobject]]::new()
    foreach ($event in $events) {
        $timeStamp = $null
        if ($event.TimeCreated) {
            try {
                $timeStamp = $event.TimeCreated.ToUniversalTime().ToString('o')
            } catch {
                $timeStamp = $event.TimeCreated.ToString('o')
            }
        }

        $results.Add([pscustomobject]@{
            Id          = $event.Id
            Level       = $event.LevelDisplayName
            RecordId    = $event.RecordId
            TimeCreated = $timeStamp
            Message     = $event.Message
        }) | Out-Null
    }

    return $results.ToArray()
}

function Invoke-Main {
    $now = Get-Date
    $payload = [ordered]@{
        CapturedAt         = $now.ToUniversalTime().ToString('o')
        SourceLog          = 'Microsoft-Windows-User Profile Service/Operational'
        EventIds           = @(1530, 1533)
        RecentWindowDays   = 7
        ExtendedWindowDays = 14
        Events             = Get-UserProfileServiceEvents -LookbackDays 14
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'user-profile-events.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
