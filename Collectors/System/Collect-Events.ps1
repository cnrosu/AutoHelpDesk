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

function Get-TaskSchedulerTaskName {
    param(
        [Parameter(Mandatory)]
        [System.Diagnostics.Eventing.Reader.EventRecord]$EventRecord
    )

    try {
        $xml = [xml]$EventRecord.ToXml()
        $taskNode = $xml.Event.EventData.Data | Where-Object { $_.Name -eq 'TaskName' } | Select-Object -First 1
        if ($taskNode -and $taskNode.'#text') { return [string]$taskNode.'#text' }
    } catch {
        return $null
    }

    return $null
}

function Get-TaskSchedulerEvents {
    param(
        [int]$WindowDays = 7
    )

    $filter = @{
        LogName   = 'Microsoft-Windows-TaskScheduler/Operational'
        Id        = @(101, 107, 414)
        StartTime = (Get-Date).AddDays(-1 * $WindowDays)
    }

    try {
        $events = Get-WinEvent -FilterHashtable $filter -ErrorAction Stop
    } catch {
        return [PSCustomObject]@{
            LogName = $filter.LogName
            Error   = $_.Exception.Message
        }
    }

    $results = New-Object System.Collections.Generic.List[object]

    foreach ($event in $events) {
        if (-not $event) { continue }
        $taskName = $null
        try { $taskName = Get-TaskSchedulerTaskName -EventRecord $event } catch { $taskName = $null }

        $results.Add([PSCustomObject]@{
            TimeCreated     = $event.TimeCreated
            Id              = $event.Id
            LevelDisplayName = $event.LevelDisplayName
            ProviderName    = $event.ProviderName
            Message         = $event.Message
            TaskName        = $taskName
        }) | Out-Null
    }

    return $results.ToArray()
}

function Invoke-Main {
    $payload = [ordered]@{
        System      = Get-RecentEvents -LogName 'System'
        Application = Get-RecentEvents -LogName 'Application'
        GroupPolicy = Get-RecentEvents -LogName 'Microsoft-Windows-GroupPolicy/Operational' -MaxEvents 200
        TaskScheduler = Get-TaskSchedulerEvents -WindowDays 7
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'events.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
