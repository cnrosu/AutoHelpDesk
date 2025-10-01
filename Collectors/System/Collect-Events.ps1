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

function Get-WheaEvents {
    $startTime = (Get-Date).AddDays(-14)
    $filter = @{
        LogName   = 'Microsoft-Windows-WHEA-Logger'
        Id        = @(17, 18, 19)
        StartTime = $startTime
    }

    try {
        $events = Get-WinEvent -FilterHashtable $filter -ErrorAction Stop | Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message

        foreach ($event in $events) {
            if ($event -and $event.PSObject.Properties['TimeCreated']) {
                $utc = $null
                try {
                    $utc = $event.TimeCreated.ToUniversalTime()
                } catch {
                }

                if ($utc) {
                    Add-Member -InputObject $event -MemberType NoteProperty -Name 'TimeCreatedUtc' -Value $utc -Force
                }
            }
        }

        return [PSCustomObject]@{
            StartTimeUtc = $startTime.ToUniversalTime()
            Events       = $events
        }
    } catch {
        return [PSCustomObject]@{
            LogName = 'Microsoft-Windows-WHEA-Logger'
            Error   = $_.Exception.Message
        }
    }
}

function Invoke-Main {
    $payload = [ordered]@{
        System      = Get-RecentEvents -LogName 'System'
        Application = Get-RecentEvents -LogName 'Application'
        GroupPolicy = Get-RecentEvents -LogName 'Microsoft-Windows-GroupPolicy/Operational' -MaxEvents 200
        WheaLogger  = Get-WheaEvents
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'events.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
