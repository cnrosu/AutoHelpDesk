<#!
.SYNOPSIS
    Collects recent Windows Update Client events for failure analysis.
.DESCRIPTION
    Queries the Microsoft-Windows-WindowsUpdateClient/Operational log for key installation
    and download events (IDs 19, 20, 25, 31, 34) within the last 14 days. The events are
    exported with basic metadata plus parsed EventData fields so analyzers can correlate
    repeated failures by HRESULT.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\\CollectorCommon.ps1')

function Convert-WindowsUpdateEvent {
    param(
        [Parameter(Mandatory)]
        [System.Diagnostics.Eventing.Reader.EventRecord]$Event
    )

    $record = [ordered]@{
        TimeCreated     = if ($Event.TimeCreated) { $Event.TimeCreated.ToString('o') } else { $null }
        Id              = $Event.Id
        LevelDisplayName = $Event.LevelDisplayName
        ProviderName    = $Event.ProviderName
        RecordId        = $Event.RecordId
    }

    try {
        $message = $Event.FormatDescription()
        if ($message) {
            $record['Message'] = $message
        }
    } catch {
        $record['MessageError'] = $_.Exception.Message
    }

    try {
        $xml = [xml]$Event.ToXml()
        if ($xml.Event -and $xml.Event.EventData -and $xml.Event.EventData.Data) {
            $eventData = [ordered]@{}
            $index = 0
            foreach ($node in $xml.Event.EventData.Data) {
                $name = if ($node.Name) { [string]$node.Name } else { "Data$index" }
                if ($eventData.Contains($name)) {
                    $name = "{0}_{1}" -f $name, $index
                }
                $value = $null
                if ($node.'#text') {
                    $value = [string]$node.'#text'
                }
                $eventData[$name] = $value
                $index++
            }

            if ($eventData.Count -gt 0) {
                $record['EventData'] = [pscustomobject]$eventData
            }
        }
    } catch {
        $record['EventDataError'] = $_.Exception.Message
    }

    return [pscustomobject]$record
}

function Invoke-Main {
    $windowEnd = Get-Date
    $windowStart = $windowEnd.AddDays(-14)

    $payload = [ordered]@{
        WindowStart = $windowStart.ToUniversalTime().ToString('o')
        WindowEnd   = $windowEnd.ToUniversalTime().ToString('o')
        Events      = @()
    }

    try {
        $filter = @{ LogName = 'Microsoft-Windows-WindowsUpdateClient/Operational'; Id = @(19, 20, 25, 31, 34); StartTime = $windowStart }
        $rawEvents = Get-WinEvent -FilterHashtable $filter -ErrorAction Stop
        $payload.Events = @()
        foreach ($event in $rawEvents) {
            $payload.Events += Convert-WindowsUpdateEvent -Event $event
        }
    } catch {
        $payload['Error'] = $_.Exception.Message
        $payload['ErrorSource'] = 'Get-WinEvent Microsoft-Windows-WindowsUpdateClient/Operational'
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'windows-update-events.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
