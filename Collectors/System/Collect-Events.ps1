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

function Get-AppLockerEvents {
    param(
        [Parameter(Mandatory)]
        [string]$LogName,

        [int]$WindowDays = 7,

        [int]$MaxEvents = 400
    )

    $now = Get-Date
    $windowStart = $now.AddDays(-[math]::Abs($WindowDays))

    $result = [ordered]@{
        LogName     = $LogName
        QueryTime   = $now.ToString('o')
        WindowStart = $windowStart.ToString('o')
        WindowDays  = [math]::Abs($WindowDays)
        Events      = @()
        Status      = 'Unknown'
    }

    try {
        $entries = Get-WinEvent -FilterHashtable @{ LogName = $LogName; StartTime = $windowStart } -ErrorAction Stop |
            Sort-Object TimeCreated -Descending |
            Select-Object -First $MaxEvents -Property TimeCreated, Id, LevelDisplayName, ProviderName, TaskDisplayName, Message, UserId

        $result.Status = 'Success'
        if ($entries) {
            $result.Events = @($entries)
        }
    } catch {
        $result.Status = 'Error'
        $result.Error = $_.Exception.Message
    }

    return [pscustomobject]$result
}

function Invoke-Main {
    $payload = [ordered]@{
        System      = Get-RecentEvents -LogName 'System'
        Application = Get-RecentEvents -LogName 'Application'
        GroupPolicy = Get-RecentEvents -LogName 'Microsoft-Windows-GroupPolicy/Operational' -MaxEvents 200
        AppLocker   = [ordered]@{
            WindowDays   = 7
            ExeAndDll    = Get-AppLockerEvents -LogName 'Microsoft-Windows-AppLocker/EXE and DLL'
            MsiAndScript = Get-AppLockerEvents -LogName 'Microsoft-Windows-AppLocker/MSI and Script'
        }
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'events.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
