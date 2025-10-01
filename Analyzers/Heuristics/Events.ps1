<#!
.SYNOPSIS
    Event log heuristics summarizing recent error and warning volume.
#>

. (Join-Path -Path (Split-Path $PSScriptRoot -Parent) -ChildPath 'AnalyzerCommon.ps1')

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

                        $gpoFailureIds = @(1058, 1030, 1129)
                        $gpoFailureEvents = @()
                        foreach ($entry in $entries) {
                            if (-not $entry) { continue }
                            if ($entry.Id -notin $gpoFailureIds) { continue }
                            if (-not $entry.PSObject.Properties['TimeCreated']) { continue }
                            $eventTime = $null
                            try {
                                $eventTime = [datetime]$entry.TimeCreated
                            } catch {
                                $eventTime = $null
                            }
                            if (-not $eventTime) { continue }
                            $gpoFailureEvents += [pscustomobject]@{
                                Event = $entry
                                Time  = $eventTime
                            }
                        }

                        if ($gpoFailureEvents.Count -gt 0) {
                            $now = Get-Date
                            $recentWindowStart = $now.AddHours(-24)
                            $historicWindowStart = $now.AddDays(-7)
                            $recentFailures = @($gpoFailureEvents | Where-Object { $_.Time -ge $recentWindowStart })
                            if ($recentFailures.Count -ge 3) {
                                $olderFailures = @($gpoFailureEvents | Where-Object { $_.Time -lt $recentWindowStart -and $_.Time -ge $historicWindowStart })
                                $lastEvent = $recentFailures | Sort-Object -Property Time -Descending | Select-Object -First 1
                                $eventIdSet = $recentFailures | ForEach-Object { $_.Event.Id } | Sort-Object -Unique
                                $lastUtc = if ($lastEvent -and $lastEvent.Time) { $lastEvent.Time.ToUniversalTime().ToString('o') } else { $null }
                                $severity = if ($olderFailures.Count -gt 0) { 'high' } else { 'medium' }
                                $evidence = [ordered]@{
                                    eventIdSet = $eventIdSet
                                    count24h   = $recentFailures.Count
                                    lastUtc    = $lastUtc
                                    hint       = 'Check DNS to DC, SYSVOL/DFS, network at startup.'
                                }
                                Add-CategoryIssue -CategoryResult $result -Severity $severity -Title 'Group Policy processing failures detected' -Evidence $evidence -Subcategory $logSubcategory
                            }
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
        }
    } else {
        Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Event log artifact missing, so noisy or unhealthy logs may be hidden.' -Subcategory 'Collection'
    }

    return $result
}
