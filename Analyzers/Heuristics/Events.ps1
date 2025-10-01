<#!
.SYNOPSIS
    Event log heuristics summarizing recent error and warning volume.
#>

. (Join-Path -Path (Split-Path $PSScriptRoot -Parent) -ChildPath 'AnalyzerCommon.ps1')

function Get-TaskSchedulerMaskedName {
    param([string]$TaskName)

    if ([string]::IsNullOrWhiteSpace($TaskName)) { return $null }

    $hashAlgorithm = $null
    try {
        $hashAlgorithm = [System.Security.Cryptography.SHA256]::Create()
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($TaskName)
        $hash = $hashAlgorithm.ComputeHash($bytes)
        return ([System.BitConverter]::ToString($hash)).Replace('-', '').ToLowerInvariant()
    } catch {
        return $null
    } finally {
        if ($hashAlgorithm) { $hashAlgorithm.Dispose() }
    }
}

function ConvertTo-EventDateTime {
    param($Value)

    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { return [datetime]$Value }

    $text = $Value.ToString()
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }

    $parsed = [datetime]::MinValue
    $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
    if ([datetime]::TryParse($text, [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$parsed)) {
        return $parsed
    }

    $styles = [System.Globalization.DateTimeStyles]::AssumeLocal
    if ([datetime]::TryParse($text, [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$parsed)) {
        return $parsed
    }

    try {
        return [datetime]::Parse($text)
    } catch {
        return $null
    }
}

function Invoke-EventsHeuristics {
    param(
        [Parameter(Mandatory)]
        $Context
    )

    Write-HeuristicDebug -Source 'Events' -Message 'Starting event log heuristics' -Data ([ordered]@{
        ArtifactCount = if ($Context -and $Context.Artifacts) { $Context.Artifacts.Count } else { 0 }
    })

    $result = New-CategoryResult -Name 'Events'

    $eventsArtifact = Get-AnalyzerArtifact -Context $Context -Name 'events'
    Write-HeuristicDebug -Source 'Events' -Message 'Resolved events artifact' -Data ([ordered]@{
        Found = [bool]$eventsArtifact
    })
    if ($eventsArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $eventsArtifact)
        Write-HeuristicDebug -Source 'Events' -Message 'Resolved events payload' -Data ([ordered]@{
            HasPayload = [bool]$payload
        })
        if ($payload) {
            foreach ($logName in @('System','Application','GroupPolicy')) {
                Write-HeuristicDebug -Source 'Events' -Message ('Inspecting {0} log entries' -f $logName)
                if (-not $payload.PSObject.Properties[$logName]) { continue }
                $entries = $payload.$logName
                if ($entries -and -not $entries.Error) {
                    $logSubcategory = ("{0} Event Log" -f $logName)
                    $errorCount = ($entries | Where-Object { $_.LevelDisplayName -eq 'Error' }).Count
                    $warnCount = ($entries | Where-Object { $_.LevelDisplayName -eq 'Warning' }).Count
                    Add-CategoryCheck -CategoryResult $result -Name ("{0} log errors" -f $logName) -Status ([string]$errorCount)
                    Add-CategoryCheck -CategoryResult $result -Name ("{0} log warnings" -f $logName) -Status ([string]$warnCount)
                    if ($logName -eq 'GroupPolicy') {
                        if ($errorCount -gt 0) {
                            Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Group Policy Operational log errors detected, indicating noisy or unhealthy logs.' -Evidence ("Errors: {0}" -f $errorCount) -Subcategory $logSubcategory
                        }
                    } else {
                        if ($errorCount -gt 20) {
                            Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title ("{0} log shows many errors ({1} in recent sample), indicating noisy or unhealthy logs." -f $logName, $errorCount) -Evidence ("Errors recorded: {0}" -f $errorCount) -Subcategory $logSubcategory
                        }
                        if ($warnCount -gt 40) {
                            Add-CategoryIssue -CategoryResult $result -Severity 'low' -Title ("Many warnings in {0} log, indicating noisy or unhealthy logs." -f $logName) -Subcategory $logSubcategory
                        }
                    }
                } elseif ($entries.Error) {
                    $logSubcategory = ("{0} Event Log" -f $logName)
                    Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title ("Unable to read {0} event log, so noisy or unhealthy logs may be hidden." -f $logName) -Evidence $entries.Error -Subcategory $logSubcategory
                }
            }

            if ($payload.PSObject.Properties['TaskScheduler']) {
                $schedulerEntries = $payload.TaskScheduler
                if ($schedulerEntries -and -not $schedulerEntries.Error) {
                    $monitoredIds = @(101, 107, 414)
                    $windowUtc = (Get-Date).ToUniversalTime().AddDays(-7)
                    $normalized = foreach ($entry in $schedulerEntries) {
                        if (-not $entry) { continue }
                        if (-not $entry.PSObject.Properties['TaskName']) { continue }
                        $taskName = [string]$entry.TaskName
                        if ([string]::IsNullOrWhiteSpace($taskName)) { continue }

                        $eventId = $null
                        if ($entry.PSObject.Properties['Id']) {
                            try { $eventId = [int]$entry.Id } catch { $eventId = $null }
                        }
                        if ($null -eq $eventId -or ($monitoredIds -notcontains $eventId)) { continue }

                        $timeValue = $null
                        if ($entry.PSObject.Properties['TimeCreated']) {
                            $timeValue = ConvertTo-EventDateTime -Value $entry.TimeCreated
                        }
                        if (-not $timeValue) { continue }
                        $timeUtc = $timeValue.ToUniversalTime()
                        if ($timeUtc -lt $windowUtc) { continue }

                        [pscustomobject]@{
                            TaskName = $taskName
                            EventId  = $eventId
                            TimeUtc  = $timeUtc
                        }
                    }

                    if ($normalized) {
                        $groups = $normalized | Group-Object -Property TaskName -CaseSensitive:$false
                        $findings = New-Object System.Collections.Generic.List[object]

                        foreach ($group in $groups) {
                            if (-not $group -or -not $group.Group) { continue }
                            $eventCount = $group.Count
                            if ($eventCount -lt 3) { continue }

                            $representative = $group.Group | Select-Object -First 1
                            $taskName = if ($representative) { [string]$representative.TaskName } else { $group.Name }

                            $lastUtc = $group.Group | Sort-Object -Property TimeUtc -Descending | Select-Object -First 1
                            $lastUtcText = $null
                            if ($lastUtc -and $lastUtc.TimeUtc) {
                                $lastUtcText = $lastUtc.TimeUtc.ToString('yyyy-MM-ddTHH:mm:ssZ')
                            }

                            $maskedName = Get-TaskSchedulerMaskedName -TaskName $taskName

                            $findings.Add([ordered]@{
                                taskNameMasked = $maskedName
                                count          = $eventCount
                                lastUtc        = $lastUtcText
                            }) | Out-Null
                        }

                        if ($findings.Count -gt 0) {
                            $evidence = $findings | Sort-Object -Property count, lastUtc -Descending
                            Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Scheduled task failures detected' -Evidence $evidence -Subcategory 'Task Scheduler'
                        }
                    }
                } elseif ($schedulerEntries.Error) {
                    Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Unable to read Task Scheduler operational log, so scheduled task failures may be hidden.' -Evidence $schedulerEntries.Error -Subcategory 'Task Scheduler'
                }
            }
        }
    } else {
        Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Event log artifact missing, so noisy or unhealthy logs may be hidden.' -Subcategory 'Collection'
    }

    return $result
}
