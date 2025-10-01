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

function Get-ProfileListSnapshot {
    $profileRoot = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'

    if (-not (Test-Path -LiteralPath $profileRoot)) {
        return [ordered]@{
            Entries = @()
            Error   = $null
        }
    }

    try {
        $entries = Get-ChildItem -LiteralPath $profileRoot -ErrorAction Stop | ForEach-Object {
            $item = $_
            $properties = $null
            try {
                $properties = Get-ItemProperty -LiteralPath $item.PSPath -ErrorAction Stop
            } catch {
            }

            $sid = $item.PSChildName
            $profilePath = $null
            $state = $null
            $flags = $null

            if ($properties) {
                if ($properties.PSObject.Properties['ProfileImagePath']) {
                    $profilePath = [string]$properties.ProfileImagePath
                }
                if ($properties.PSObject.Properties['State']) {
                    $state = [int64]$properties.State
                }
                if ($properties.PSObject.Properties['Flags']) {
                    $flags = [int64]$properties.Flags
                }
            }

            [pscustomobject]@{
                Sid              = $sid
                SidTail          = if ($sid) { ($sid -split '-')[-1] } else { $null }
                ProfileImagePath = $profilePath
                State            = $state
                Flags            = $flags
                LastWriteTimeUtc = $item.LastWriteTime.ToUniversalTime().ToString('o')
            }
        }

        return [ordered]@{
            Entries = $entries
            Error   = $null
        }
    } catch {
        return [ordered]@{
            Entries = @()
            Error   = $_.Exception.Message
        }
    }
}

function Get-UserProfileServiceEvents {
    param(
        [Parameter(Mandatory)]
        [hashtable]$ProfileMap,

        [int]$CollectionWindowDays = 14
    )

    $eventIds = @(1511, 1515, 1518, 1530, 1533)
    $windowStart = (Get-Date).AddDays(-1 * [double]$CollectionWindowDays)
    $logCandidates = @('Microsoft-Windows-User Profile Service/Operational', 'System')
    $errors = New-Object System.Collections.Generic.List[pscustomobject]
    $selectedLog = $null
    $collectedEvents = @()

    foreach ($logName in $logCandidates) {
        try {
            $filter = @{
                LogName   = $logName
                Id        = $eventIds
                StartTime = $windowStart
            }

            $events = @(Get-WinEvent -FilterHashtable $filter -ErrorAction Stop | Sort-Object -Property TimeCreated -Descending)
            $selectedLog = $logName

            if ($events.Count -eq 0) {
                $collectedEvents = @()
            } else {
                $collectedEvents = foreach ($evt in $events) {
                    $sid = $null

                    if ($evt.PSObject.Properties['UserId'] -and $evt.UserId) {
                        try {
                            $sid = $evt.UserId.Value
                        } catch {
                            $sid = [string]$evt.UserId
                        }
                    }

                    if (-not $sid -and $evt.Properties) {
                        foreach ($prop in $evt.Properties) {
                            if ($null -eq $prop) { continue }
                            $value = $prop.Value
                            if ($value -is [System.Security.Principal.SecurityIdentifier]) {
                                $sid = $value.Value
                                break
                            }
                            if ($value -is [string] -and $value -match '^S-1-5-') {
                                $sid = $value
                                break
                            }
                        }
                    }

                    $profilePath = $null
                    if ($sid -and $ProfileMap.ContainsKey($sid)) {
                        $profilePath = $ProfileMap[$sid].ProfileImagePath
                    }

                    [pscustomobject]@{
                        TimeCreated       = $evt.TimeCreated
                        Id                = $evt.Id
                        LevelDisplayName  = $evt.LevelDisplayName
                        ProviderName      = if ($evt.PSObject.Properties['ProviderName']) { $evt.ProviderName } else { $null }
                        Message           = $evt.Message
                        RecordId          = if ($evt.PSObject.Properties['RecordId']) { $evt.RecordId } else { $null }
                        Sid               = $sid
                        SidTail           = if ($sid) { ($sid -split '-')[-1] } else { $null }
                        ProfilePath       = $profilePath
                    }
                }
            }

            if ($errors.Count -gt 0) {
                $errors.Clear()
            }

            break
        } catch {
            $errors.Add([pscustomobject]@{
                LogName = $logName
                Error   = $_.Exception.Message
            }) | Out-Null
        }
    }

    if (-not $selectedLog) {
        $selectedLog = $logCandidates[-1]
    }

    return [ordered]@{
        LogName              = $selectedLog
        Events               = $collectedEvents
        CollectionWindowDays = $CollectionWindowDays
        Errors               = if ($errors.Count -gt 0) { $errors } else { $null }
    }
}

function Invoke-Main {
    $profileSnapshot = Get-ProfileListSnapshot
    $profileMap = @{}
    foreach ($entry in $profileSnapshot.Entries) {
        if ($entry.Sid) {
            $profileMap[$entry.Sid] = $entry
        }
    }

    $userProfileEvents = Get-UserProfileServiceEvents -ProfileMap $profileMap

    $payload = [ordered]@{
        System            = Get-RecentEvents -LogName 'System'
        Application       = Get-RecentEvents -LogName 'Application'
        GroupPolicy       = Get-RecentEvents -LogName 'Microsoft-Windows-GroupPolicy/Operational' -MaxEvents 200
        UserProfileService = [ordered]@{
            Events               = $userProfileEvents.Events
            LogName              = $userProfileEvents.LogName
            CollectionWindowDays = $userProfileEvents.CollectionWindowDays
            Errors               = $userProfileEvents.Errors
            ProfileList          = $profileSnapshot
        }
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'events.json' -Data $result -Depth 8
    Write-Output $outputPath
}

Invoke-Main
