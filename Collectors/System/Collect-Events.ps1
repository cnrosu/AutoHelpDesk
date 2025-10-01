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

function Get-WindowsUpdateClientEvents {
    param(
        [int]$MaxEvents = 200
    )

    $logName = 'Microsoft-Windows-WindowsUpdateClient/Operational'
    $xpath = "*[System[(EventID=19 or EventID=20 or EventID=25 or EventID=31 or EventID=34)]]"

    try {
        return Get-WinEvent -LogName $logName -FilterXPath $xpath -MaxEvents $MaxEvents -ErrorAction Stop |
            Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message
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
        WindowsUpdateClient = Get-WindowsUpdateClientEvents -MaxEvents 200
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'events.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
