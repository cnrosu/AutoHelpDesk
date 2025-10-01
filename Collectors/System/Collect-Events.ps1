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

function Get-WmiActivityEvents {
    param(
        [int]$WindowDays = 7
    )

    $logName = 'Microsoft-Windows-WMI-Activity/Operational'
    $startTime = (Get-Date).AddDays(-[math]::Abs($WindowDays))

    try {
        $filter = @{
            LogName   = $logName
            Id        = @(10, 5858, 5859)
            StartTime = $startTime
        }

        return Get-WinEvent -FilterHashtable $filter -ErrorAction Stop |
            Sort-Object -Property TimeCreated -Descending |
            ForEach-Object {
                $message = $_.Message
                if ($message -and $message.Length -gt 200) {
                    $message = $message.Substring(0, 200)
                }

                [pscustomobject]@{
                    TimeCreated      = $_.TimeCreated
                    Id               = $_.Id
                    LevelDisplayName = $_.LevelDisplayName
                    ProviderName     = $_.ProviderName
                    Message          = $message
                }
            }
    } catch {
        return [PSCustomObject]@{
            LogName = $logName
            Error   = $_.Exception.Message
        }
    }
}

function Invoke-Main {
    $payload = [ordered]@{
        System      = Get-RecentEvents -LogName 'System'
        Application = Get-RecentEvents -LogName 'Application'
        GroupPolicy = Get-RecentEvents -LogName 'Microsoft-Windows-GroupPolicy/Operational' -MaxEvents 200
        WmiActivity = Get-WmiActivityEvents
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'events.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
