<#!
.SYNOPSIS
    Collects recent Security log authentication events for account lockout analysis.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\output'),

    [int]$MaxLockoutEvents = 200,
    [int]$MaxFailedEvents = 500,
    [int]$MaxSuccessEvents = 200
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\CollectorCommon.ps1')

function Convert-AuthenticationEvent {
    param($Event)

    if (-not $Event) { return $null }

    $record = [ordered]@{
        Id          = $Event.Id
        Level       = $Event.LevelDisplayName
        Provider    = $Event.ProviderName
        MachineName = $Event.MachineName
        RecordId    = $Event.RecordId
        TimeCreated = if ($Event.TimeCreated) { $Event.TimeCreated.ToUniversalTime().ToString('o') } else { $null }
    }

    if ($Event.Message) {
        $record['Message'] = ($Event.Message -replace '\s+', ' ').Trim()
    }

    try {
        $xml = [xml]$Event.ToXml()
        if ($xml -and $xml.Event) {
            $properties = [ordered]@{}
            if ($xml.Event.EventData -and $xml.Event.EventData.Data) {
                foreach ($dataNode in $xml.Event.EventData.Data) {
                    if (-not $dataNode) { continue }
                    $name = $dataNode.Name
                    if (-not $name) { continue }
                    $value = $null
                    if ($dataNode.'#text') {
                        $value = [string]$dataNode.'#text'
                    } elseif ($dataNode.InnerText) {
                        $value = [string]$dataNode.InnerText
                    }
                    $properties[$name] = $value
                }
            }

            if ($properties.Count -gt 0) {
                $record['Properties'] = $properties
            }
        }
    } catch {
        $record['ParseError'] = $_.Exception.Message
    }

    return $record
}

function Get-SecurityEvents {
    param(
        [Parameter(Mandatory)]
        [int[]]$Ids,

        [Parameter(Mandatory)]
        [int]$MaxEvents,

        [datetime]$StartTime
    )

    $events = @()
    try {
        $events = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = $Ids; StartTime = $StartTime } -ErrorAction Stop
    } catch {
        return [pscustomobject]@{ Error = $_.Exception.Message }
    }

    if (-not $events) { return @() }

    $sorted = $events | Sort-Object TimeCreated -Descending
    if ($MaxEvents -gt 0 -and $sorted.Count -gt $MaxEvents) {
        $sorted = $sorted | Select-Object -First $MaxEvents
    }

    $orderedEvents = $sorted | Sort-Object TimeCreated
    $converted = [System.Collections.Generic.List[object]]::new()
    foreach ($evt in $orderedEvents) {
        $converted.Add((Convert-AuthenticationEvent $evt)) | Out-Null
    }

    return $converted.ToArray()
}

function Filter-LogonType {
    param(
        [Parameter(Mandatory)]
        $Events,

        [string]$LogonType
    )

    if (-not $Events) { return @() }

    $filtered = [System.Collections.Generic.List[object]]::new()
    foreach ($evt in $Events) {
        if (-not $evt) { continue }
        if (-not ($evt.PSObject.Properties['Properties'])) { continue }
        $props = $evt.Properties
        if (-not $props) { continue }
        $value = $props['LogonType']
        if ($value -and $value.ToString() -eq $LogonType) {
            $filtered.Add($evt) | Out-Null
        }
    }

    return $filtered.ToArray()
}

function Invoke-Main {
    $startTime = (Get-Date).AddDays(-7)

    $lockoutEvents = Get-SecurityEvents -Ids @(4740) -MaxEvents $MaxLockoutEvents -StartTime $startTime
    $failedEvents = Get-SecurityEvents -Ids @(4625) -MaxEvents $MaxFailedEvents -StartTime $startTime

    $successEvents = Get-SecurityEvents -Ids @(4624) -MaxEvents $MaxSuccessEvents -StartTime $startTime
    if ($successEvents -is [System.Collections.IEnumerable] -and -not ($successEvents -is [string])) {
        $successEvents = Filter-LogonType -Events $successEvents -LogonType '3'
    }

    $payload = [ordered]@{
        WindowStartUtc       = $startTime.ToUniversalTime().ToString('o')
        LockoutEvents        = $lockoutEvents
        FailedLogonEvents    = $failedEvents
        SuccessfulLogonType3 = $successEvents
    }

    if ($lockoutEvents -is [pscustomobject] -and $lockoutEvents.PSObject.Properties['Error']) {
        $payload.LockoutEvents = @()
        $payload['LockoutError'] = $lockoutEvents.Error
    }

    if ($failedEvents -is [pscustomobject] -and $failedEvents.PSObject.Properties['Error']) {
        $payload.FailedLogonEvents = @()
        $payload['FailedLogonError'] = $failedEvents.Error
    }

    if ($successEvents -is [pscustomobject] -and $successEvents.PSObject.Properties['Error']) {
        $payload.SuccessfulLogonType3 = @()
        $payload['SuccessfulLogonError'] = $successEvents.Error
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'events-authentication.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
