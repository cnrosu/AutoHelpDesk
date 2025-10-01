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
            $systemEntries = $null
            foreach ($logName in @('System','Application','GroupPolicy')) {
                Write-HeuristicDebug -Source 'Events' -Message ('Inspecting {0} log entries' -f $logName)
                if (-not $payload.PSObject.Properties[$logName]) { continue }
                $entries = $payload.$logName
                if ($logName -eq 'System') { $systemEntries = $entries }
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

            if ($systemEntries) {
                $systemEntryCount = ($systemEntries | Measure-Object).Count
                Write-HeuristicDebug -Source 'Events' -Message 'Evaluating display driver resets (Event 4101)' -Data ([ordered]@{
                    Entries = $systemEntryCount
                })
            }

            if ($systemEntries -and -not $systemEntries.Error) {
                $windowStart = (Get-Date).AddDays(-7)
                $tdrEvents = @(
                    foreach ($entry in $systemEntries) {
                        if (-not $entry) { continue }
                        if (-not ($entry.PSObject.Properties['Id'])) { continue }
                        if ($entry.Id -ne 4101) { continue }

                        $eventTime = $null
                        if ($entry.PSObject.Properties['TimeCreated'] -and $entry.TimeCreated) {
                            try {
                                $eventTime = [datetime]$entry.TimeCreated
                            } catch {
                                $eventTime = $null
                            }
                        }

                        if (-not $eventTime -or $eventTime -lt $windowStart) { continue }
                        $entry
                    }
                )

                Write-HeuristicDebug -Source 'Events' -Message 'Display driver reset candidates within window' -Data ([ordered]@{
                    Count = $tdrEvents.Count
                })

                if ($tdrEvents.Count -ge 2) {
                    $latestEvent = $tdrEvents | Sort-Object -Property TimeCreated -Descending | Select-Object -First 1
                    $lastOccurrenceUtc = $null
                    if ($latestEvent -and $latestEvent.PSObject.Properties['TimeCreated'] -and $latestEvent.TimeCreated) {
                        try {
                            $lastOccurrenceUtc = ([datetime]$latestEvent.TimeCreated).ToUniversalTime().ToString('u')
                        } catch {
                            $lastOccurrenceUtc = $null
                        }
                    }

                    $adapterHint = $null
                    foreach ($candidate in ($tdrEvents | Sort-Object -Property TimeCreated -Descending)) {
                        if (-not $candidate -or -not $candidate.PSObject.Properties['Message']) { continue }
                        $messageText = [string]$candidate.Message
                        if (-not $messageText) { continue }
                        $match = [System.Text.RegularExpressions.Regex]::Match(
                            $messageText,
                            'Display driver\s+(?<adapter>[\w\-. ]+?)\s+stopped responding',
                            [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
                        )
                        if ($match.Success) {
                            $adapterHint = $match.Groups['adapter'].Value.Trim()
                            if ($adapterHint) { break }
                        }
                    }

                    $evidence = [ordered]@{
                        Count            = $tdrEvents.Count
                        LastOccurrenceUtc = $lastOccurrenceUtc
                    }
                    if ($adapterHint) {
                        $evidence['AdapterHint'] = $adapterHint
                    }

                    Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Display driver resets detected (Event 4101)' -Evidence $evidence -Subcategory 'Display / GPU'
                }
            }
        }
    } else {
        Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Event log artifact missing, so noisy or unhealthy logs may be hidden.' -Subcategory 'Collection'
    }

    return $result
}
