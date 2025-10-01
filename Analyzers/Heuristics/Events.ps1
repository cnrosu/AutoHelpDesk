<#!
.SYNOPSIS
    Event log heuristics summarizing recent error and warning volume.
#>

function Get-W32tmStatusSummary {
    param(
        $Status
    )

    $summary = [ordered]@{
        OffsetSeconds = $null
        Source        = $null
        LastSyncTime  = $null
    }

    if (-not $Status) { return [pscustomobject]$summary }

    if ($Status.Output) {
        $offsetValue = $null
        foreach ($line in $Status.Output) {
            if (-not $summary.Source -and $line -match 'Source:\s*(?<value>.+)$') {
                $summary.Source = $matches['value'].Trim()
                continue
            }

            if (-not $summary.LastSyncTime -and $line -match 'Last Successful Sync Time:\s*(?<value>.+)$') {
                $rawValue = $matches['value'].Trim()
                if ($rawValue -and $rawValue -notmatch '(?i)unspecified') {
                    try {
                        $parsed = Get-Date -Date $rawValue -ErrorAction Stop
                        $summary.LastSyncTime = $parsed
                    } catch {
                    }
                }
                continue
            }

            if ($line -match '(?i)(?:phase\s+offset|clock\s+skew|offset):\s*(?<value>[-+]?\d+(?:\.\d+)?)s') {
                try {
                    $offsetValue = [double]$matches['value']
                } catch {
                    $offsetValue = $null
                }
            }
        }

        if ($null -ne $offsetValue) {
            $summary.OffsetSeconds = [int][math]::Round($offsetValue, 0)
        }
    }

    if (-not $summary.Source -and $Status.FilePath) {
        $summary.Source = [System.IO.Path]::GetFileName($Status.FilePath)
    }

    return [pscustomobject]$summary
}

function Get-TimeServiceEventSummary {
    param(
        $Events
    )

    $summary = [ordered]@{
        OffsetSeconds   = $null
        OffsetSource    = $null
        OffsetEventTime = $null
        ProblemEvents   = @()
        CollectionError = $null
    }

    if (-not $Events) { return [pscustomobject]$summary }

    $problemIds = @(36, 47, 50)

    foreach ($event in $Events) {
        if (-not $event) { continue }

        if ($event.PSObject.Properties['Error']) {
            $summary.CollectionError = $event.Error
            continue
        }

        if ($problemIds -contains [int]$event.Id) {
            $summary.ProblemEvents += ,$event
        }

        if ($null -eq $summary.OffsetSeconds -and $event.Message) {
            $message = [string]$event.Message
            if ($message -match '(?i)(?<seconds>[-+]?\d+(?:\.\d+)?)\s*seconds') {
                try {
                    $seconds = [double]$matches['seconds']
                    $summary.OffsetSeconds = [int][math]::Round($seconds, 0)
                    $summary.OffsetSource = "Event {0}" -f $event.Id
                    $summary.OffsetEventTime = $event.TimeCreated
                    continue
                } catch {
                }
            }

            if ($message -match '(?i)(?<milliseconds>[-+]?\d+(?:\.\d+)?)\s*(?:milliseconds|ms)') {
                try {
                    $milliseconds = [double]$matches['milliseconds']
                    $seconds = $milliseconds / 1000
                    $summary.OffsetSeconds = [int][math]::Round($seconds, 0)
                    $summary.OffsetSource = "Event {0}" -f $event.Id
                    $summary.OffsetEventTime = $event.TimeCreated
                } catch {
                }
            }
        }
    }

    return [pscustomobject]$summary
}

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

            $timeService = if ($payload.PSObject.Properties['TimeService']) { $payload.TimeService } else { $null }
            if ($timeService) {
                $operationalEvents = if ($timeService.PSObject.Properties['Operational']) { $timeService.Operational } else { $null }
                $status = if ($timeService.PSObject.Properties['W32tmStatus']) { $timeService.W32tmStatus } else { $null }

                $statusSummary = Get-W32tmStatusSummary -Status $status
                $eventSummary = Get-TimeServiceEventSummary -Events $operationalEvents

                if ($eventSummary.CollectionError) {
                    Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Time service events unavailable, so drift alerts may be missed.' -Evidence $eventSummary.CollectionError -Subcategory 'Time Service'
                }

                $offsetSeconds = $statusSummary.OffsetSeconds
                $offsetSource = $statusSummary.Source
                $lastSyncTime = $statusSummary.LastSyncTime

                if ($null -eq $offsetSeconds -and $null -ne $eventSummary.OffsetSeconds) {
                    $offsetSeconds = $eventSummary.OffsetSeconds
                    $offsetSource = $eventSummary.OffsetSource
                    if (-not $lastSyncTime -and $eventSummary.OffsetEventTime) {
                        $lastSyncTime = $eventSummary.OffsetEventTime
                    }
                }

                if (-not $offsetSource -and $eventSummary.OffsetSource) {
                    $offsetSource = $eventSummary.OffsetSource
                }

                if (-not $lastSyncTime -and $eventSummary.OffsetEventTime) {
                    $lastSyncTime = $eventSummary.OffsetEventTime
                }

                $lastSyncUtc = if ($lastSyncTime) { $lastSyncTime.ToUniversalTime().ToString('o') } else { $null }
                $absOffset = if ($null -ne $offsetSeconds) { [math]::Abs($offsetSeconds) } else { $null }
                $hasProblemEvents = ($eventSummary.ProblemEvents -and $eventSummary.ProblemEvents.Count -gt 0)

                if (-not $offsetSource -and $hasProblemEvents) {
                    $offsetSource = 'Time-Service events'
                }

                $evidence = [ordered]@{
                    offsetSec   = $offsetSeconds
                    source      = $offsetSource
                    lastSyncUtc = $lastSyncUtc
                }

                $issueCondition = $hasProblemEvents -or ($null -ne $absOffset -and $absOffset -gt 300)
                if ($issueCondition) {
                    Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'System clock drift beyond 5 minutes' -Evidence ([pscustomobject]$evidence) -Subcategory 'Time Service'
                } elseif ($null -ne $absOffset -and $absOffset -le 60 -and $lastSyncTime) {
                    $ageHours = (Get-Date).ToUniversalTime() - $lastSyncTime.ToUniversalTime()
                    if ($ageHours.TotalHours -le 24) {
                        Add-CategoryNormal -CategoryResult $result -Title 'Time synchronization OK — offset ≤60s and last sync ≤24h ago' -Evidence ([pscustomobject]$evidence) -Subcategory 'Time Service'
                    }
                }
            }
        }
    } else {
        Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Event log artifact missing, so noisy or unhealthy logs may be hidden.' -Subcategory 'Collection'
    }

    return $result
}
