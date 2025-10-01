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

function Get-DcomAccessDeniedEvents {
    param(
        [int]$LookbackDays = 14
    )

    $effectiveDays = if ($LookbackDays -lt 1) { 1 } else { [int][math]::Ceiling([math]::Abs($LookbackDays)) }
    $startTime = (Get-Date).AddDays(-$effectiveDays)

    try {
        $events = Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 10016; StartTime = $startTime } -ErrorAction Stop | Select-Object TimeCreated, Message
    } catch {
        return [PSCustomObject]@{
            EventId = 10016
            Error   = $_.Exception.Message
        }
    }

    $records = New-Object System.Collections.Generic.List[object]
    foreach ($event in $events) {
        if (-not $event) { continue }

        $timeValue = $null
        if ($event.PSObject.Properties['TimeCreated'] -and $event.TimeCreated) {
            try {
                $timeValue = $event.TimeCreated.ToUniversalTime().ToString('o')
            } catch {
                try {
                    $timeValue = [datetime]$event.TimeCreated
                    if ($timeValue) { $timeValue = $timeValue.ToUniversalTime().ToString('o') }
                } catch {
                    $timeValue = $null
                }
            }
        }

        $messageValue = $null
        if ($event.PSObject.Properties['Message']) {
            try {
                $messageValue = [string]$event.Message
            } catch {
                $messageValue = $event.Message
            }
        }

        $records.Add([pscustomobject]@{
            TimeCreatedUtc = $timeValue
            Message        = $messageValue
        }) | Out-Null
    }

    return [pscustomobject]@{
        EventId       = 10016
        StartTimeUtc  = $startTime.ToUniversalTime().ToString('o')
        EventCount    = $records.Count
        Events        = $records
    }
}

function Invoke-Main {
    $payload = [ordered]@{
        System      = Get-RecentEvents -LogName 'System'
        Application = Get-RecentEvents -LogName 'Application'
        GroupPolicy = Get-RecentEvents -LogName 'Microsoft-Windows-GroupPolicy/Operational' -MaxEvents 200
        SystemDcom  = Get-DcomAccessDeniedEvents
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'events.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
