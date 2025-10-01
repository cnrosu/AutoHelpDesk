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

function Invoke-CommandCapture {
    param(
        [Parameter(Mandatory)]
        [string]$FilePath,

        [Parameter()]
        [string[]]$ArgumentList = @()
    )

    $result = [ordered]@{
        FilePath  = $FilePath
        Arguments = $ArgumentList
        Output    = @()
        ExitCode  = $null
        Error     = $null
        Succeeded = $false
    }

    try {
        $output = & $FilePath @ArgumentList 2>&1
        if ($output) {
            $result.Output = @($output)
        }
        if ($null -ne $LASTEXITCODE) {
            $result.ExitCode = $LASTEXITCODE
            if ($LASTEXITCODE -eq 0) {
                $result.Succeeded = $true
            }
        } else {
            $result.ExitCode = 0
            $result.Succeeded = $true
        }
    } catch {
        $result.Error = $_.Exception.Message
        $result.Succeeded = $false
    }

    return $result
}

function Get-TimeServiceEvents {
    param(
        [int]$Days = 14,

        [int[]]$EventIds = @(29, 36, 47, 50),

        [int]$MaxEvents = 200
    )

    $startTime = (Get-Date).AddDays(-[math]::Abs($Days))

    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName   = 'Microsoft-Windows-Time-Service/Operational'
            Id        = $EventIds
            StartTime = $startTime
        } -ErrorAction Stop | Select-Object -First $MaxEvents -Property TimeCreated, Id, LevelDisplayName, Message

        if (-not $events) { return @() }

        $normalized = foreach ($event in $events) {
            [pscustomobject]@{
                TimeCreated = $event.TimeCreated
                Id          = $event.Id
                Level       = $event.LevelDisplayName
                Message     = $event.Message
            }
        }

        return @($normalized)
    } catch {
        return @([pscustomobject]@{
            LogName = 'Microsoft-Windows-Time-Service/Operational'
            Error   = $_.Exception.Message
        })
    }
}

function Get-W32tmStatus {
    return Invoke-CommandCapture -FilePath 'w32tm.exe' -ArgumentList '/query', '/status'
}

function Invoke-Main {
    $payload = [ordered]@{
        System      = Get-RecentEvents -LogName 'System'
        Application = Get-RecentEvents -LogName 'Application'
        GroupPolicy = Get-RecentEvents -LogName 'Microsoft-Windows-GroupPolicy/Operational' -MaxEvents 200
        TimeService = [ordered]@{
            Operational = Get-TimeServiceEvents
            W32tmStatus = Get-W32tmStatus
        }
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'events.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
