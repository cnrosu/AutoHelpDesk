<#!
.SYNOPSIS
    Collects recent Application, System, and authentication/time synchronization event log entries.
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

function ConvertTo-EventPayload {
    param(
        [Parameter(Mandatory)]
        $Event
    )

    $entry = [ordered]@{
        TimeCreated      = $null
        RecordId         = $null
        Id               = $null
        LevelDisplayName = $null
        ProviderName     = $null
        Message          = $null
    }

    if ($Event.PSObject.Properties['TimeCreated']) {
        $timeValue = $Event.TimeCreated
        if ($timeValue) {
            try {
                $entry.TimeCreated = $timeValue.ToUniversalTime().ToString('o')
            } catch {
                $entry.TimeCreated = $timeValue.ToString()
            }
        }
    }

    foreach ($name in @('RecordId','Id','LevelDisplayName','ProviderName','Message')) {
        if ($Event.PSObject.Properties[$name]) {
            $entry[$name] = $Event.$name
        }
    }

    try {
        $xml = [xml]$Event.ToXml()
        $dataNodes = $xml.Event.EventData.Data
        if ($dataNodes) {
            $data = [ordered]@{}
            foreach ($node in $dataNodes) {
                $nodeName = $null
                if ($node.Name) {
                    $nodeName = [string]$node.Name
                } elseif ($node.PSObject.Properties['name']) {
                    $nodeName = [string]$node.name
                }

                if (-not $nodeName) { continue }

                $value = $null
                if ($node.'#text') {
                    $value = [string]$node.'#text'
                }

                if ($data.Contains($nodeName)) {
                    $data[$nodeName] = $value
                } else {
                    $data.Add($nodeName, $value)
                }
            }

            if ($data.Count -gt 0) {
                $entry['EventData'] = $data
            }
        }
    } catch {
        $entry['EventDataError'] = $_.Exception.Message
    }

    return [pscustomobject]$entry
}

function Get-EventRecords {
    param(
        [Parameter(Mandatory)]
        [string]$LogName,

        [int[]]$EventIds,

        [datetime]$StartTime,

        [int]$MaxEvents = 400
    )

    $result = [ordered]@{
        LogName   = $LogName
        EventIds  = if ($EventIds) { @($EventIds) } else { @() }
        StartTime = if ($StartTime) { $StartTime.ToString('o') } else { $null }
        Events    = @()
        Error     = $null
    }

    try {
        $filter = @{ LogName = $LogName }
        if ($EventIds) { $filter['Id'] = $EventIds }
        if ($StartTime) { $filter['StartTime'] = $StartTime }

        $eventRecords = Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxEvents -ErrorAction Stop
        if ($eventRecords) {
            $ordered = @($eventRecords) | Sort-Object TimeCreated
            $converted = foreach ($event in $ordered) {
                ConvertTo-EventPayload -Event $event
            }

            $result.Events = @($converted)
        }
    } catch {
        $result.Error = $_.Exception.Message
    }

    return [pscustomobject]$result
}

function Get-UserProfileServiceEvents {
    $startTime = (Get-Date).AddDays(-7)
    return Get-EventRecords -LogName 'Microsoft-Windows-User Profile Service/Operational' -EventIds @(1530, 1533) -StartTime $startTime -MaxEvents 400
}

function Get-AccountLockoutEvents {
    $startTime = (Get-Date).AddDays(-7)

    $lockouts = Get-EventRecords -LogName 'Security' -EventIds @(4740) -StartTime $startTime -MaxEvents 400
    $failed = Get-EventRecords -LogName 'Security' -EventIds @(4625) -StartTime $startTime -MaxEvents 800
    $network = Get-EventRecords -LogName 'Security' -EventIds @(4624) -StartTime $startTime -MaxEvents 400

    if ($network -and -not $network.Error -and $network.PSObject.Properties['Events']) {
        $filtered = @()
        foreach ($event in @($network.Events)) {
            if (-not $event) { continue }

            $eventData = $null
            if ($event.PSObject.Properties['EventData']) {
                $eventData = $event.EventData
            }

            $logonType = $null
            if ($eventData) {
                if ($eventData -is [System.Collections.IDictionary] -and $eventData.Contains('LogonType')) {
                    $logonType = $eventData['LogonType']
                } elseif ($eventData.PSObject -and $eventData.PSObject.Properties['LogonType']) {
                    $logonType = $eventData.LogonType
                }
            }

            if ($logonType -and [string]::Equals([string]$logonType, '3', [System.StringComparison]::OrdinalIgnoreCase)) {
                $filtered += $event
            }
        }

        $network.Events = @($filtered)
    }

    $result = [ordered]@{
        WindowDays    = 7
        Lockouts      = $lockouts
        FailedLogons  = $failed
        NetworkLogons = $network
    }

    return [pscustomobject]$result
}

function Get-KerberosPreAuthFailures {
    $startTime = (Get-Date).AddDays(-14)
    return Get-EventRecords -LogName 'Security' -EventIds @(4771) -StartTime $startTime -MaxEvents 400
}

function Get-TimeServiceEvents {
    $startTime = (Get-Date).AddDays(-14)
    return Get-EventRecords -LogName 'Microsoft-Windows-Time-Service/Operational' -EventIds @(29, 36, 47, 50) -StartTime $startTime -MaxEvents 400
}

function Get-W32tmStatus {
    $result = [ordered]@{
        CommandPath = $null
        Arguments   = @('/query','/status')
        Output      = @()
        ExitCode    = $null
        Error       = $null
        Succeeded   = $false
    }

    $command = Get-Command -Name 'w32tm.exe' -ErrorAction SilentlyContinue
    if (-not $command) {
        $result.Error = 'w32tm.exe not found.'
        return [pscustomobject]$result
    }

    $result.CommandPath = $command.Source

    try {
        $output = & $command.Source '/query' '/status' 2>&1
        if ($output) {
            $result.Output = @($output)
        }

        if ($null -ne $LASTEXITCODE) {
            $result.ExitCode = $LASTEXITCODE
            if ($LASTEXITCODE -eq 0) { $result.Succeeded = $true }
        } else {
            $result.ExitCode = 0
            $result.Succeeded = $true
        }
    } catch {
        $result.Error = $_.Exception.Message
        $result.Succeeded = $false
    }

    return [pscustomobject]$result
}

function Invoke-Main {
    $payload = [ordered]@{
        System      = Get-RecentEvents -LogName 'System'
        Application = Get-RecentEvents -LogName 'Application'
        GroupPolicy = Get-RecentEvents -LogName 'Microsoft-Windows-GroupPolicy/Operational' -MaxEvents 200
        UserProfileService = Get-UserProfileServiceEvents
        Authentication = [ordered]@{
            KerberosPreAuthFailures = Get-KerberosPreAuthFailures
            TimeServiceEvents       = Get-TimeServiceEvents
            W32tmStatus             = Get-W32tmStatus
            AccountLockouts         = Get-AccountLockoutEvents
        }
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'events.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
