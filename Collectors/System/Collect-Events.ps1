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

function Get-StorageDeviceHintFromMessage {
    param(
        [string]$Message
    )

    if ([string]::IsNullOrWhiteSpace($Message)) { return $null }

    $patterns = @(
        '\\Device\\[^\\\s\.,;:)]+',
        'Harddisk\d+(?:\\DR\d+)?',
        '(?i)volume\s+([A-Z]:)',
        '(?i)volume\s+({[^}]+})'
    )

    foreach ($pattern in $patterns) {
        $match = [regex]::Match($Message, $pattern)
        if (-not $match.Success) { continue }

        $value = $match.Value
        if ($match.Groups.Count -gt 1 -and $match.Groups[1].Success) {
            $value = $match.Groups[1].Value
        }

        if ([string]::IsNullOrWhiteSpace($value)) { continue }

        $trimmed = $value.Trim().TrimEnd('.', ';', ',', ':', ')')
        if ($trimmed.StartsWith('Volume ', [System.StringComparison]::OrdinalIgnoreCase)) {
            $trimmed = $trimmed.Substring(7).Trim()
        }

        if (-not [string]::IsNullOrWhiteSpace($trimmed)) {
            return $trimmed
        }
    }

    return $null
}

function Get-StorageDiskEventSummary {
    param(
        [Parameter(Mandatory)]
        [datetime]$StartTime
    )

    $windowStartUtc = $StartTime.ToUniversalTime()
    $result = [ordered]@{
        WindowStartUtc = $windowStartUtc.ToString('o')
    }

    try {
        $filter = @{
            LogName   = 'System'
            Id        = @(51, 55, 153)
            StartTime = $StartTime
        }

        $rawEvents = Get-WinEvent -FilterHashtable $filter -ErrorAction Stop |
            Where-Object { $_.ProviderName -in @('Disk', 'Ntfs') } |
            Select-Object TimeCreated, Id, ProviderName, Message

        $summaries = @()

        if ($rawEvents) {
            $grouped = $rawEvents | Group-Object -Property Id
            foreach ($group in $grouped) {
                if (-not $group -or -not $group.Group) { continue }

                $entries = $group.Group | Sort-Object -Property TimeCreated -Descending
                if (-not $entries -or $entries.Count -eq 0) { continue }

                $eventId = [int]$entries[0].Id
                $provider = $entries[0].ProviderName
                $lastTime = $entries[0].TimeCreated

                $deviceHints = $entries | ForEach-Object { Get-StorageDeviceHintFromMessage -Message $_.Message } |
                    Where-Object { $_ } | Select-Object -Unique

                $summary = [ordered]@{
                    EventId = $eventId
                    Count   = $entries.Count
                }

                if ($provider) { $summary.Provider = $provider }
                if ($lastTime) { $summary.LastUtc = $lastTime.ToUniversalTime().ToString('o') }

                if ($deviceHints) {
                    $normalizedHints = @()
                    foreach ($hint in $deviceHints) {
                        if ([string]::IsNullOrWhiteSpace($hint)) { continue }
                        $normalizedHints += $hint.Trim()
                    }
                    if ($normalizedHints.Count -eq 1) {
                        $summary.DeviceHint = $normalizedHints[0]
                    } elseif ($normalizedHints.Count -gt 1) {
                        $summary.DeviceHints = $normalizedHints
                    }
                }

                $summaries += [PSCustomObject]$summary
            }
        }

        $result.Events = $summaries
    } catch {
        $result.Error = $_.Exception.Message
    }

    return [PSCustomObject]$result
}

function Invoke-Main {
    $payload = [ordered]@{
        System      = Get-RecentEvents -LogName 'System'
        Application = Get-RecentEvents -LogName 'Application'
        GroupPolicy = Get-RecentEvents -LogName 'Microsoft-Windows-GroupPolicy/Operational' -MaxEvents 200
    }

    $windowStart = (Get-Date).AddDays(-7)
    $payload.StorageDiskEvents = Get-StorageDiskEventSummary -StartTime $windowStart

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'events.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
