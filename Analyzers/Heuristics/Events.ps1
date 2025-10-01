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

            if ($payload.PSObject.Properties['WmiActivity']) {
                Write-HeuristicDebug -Source 'Events' -Message 'Inspecting WMI Activity log entries'
                $entries = $payload.WmiActivity
                if ($entries -and -not $entries.Error) {
                    $eventsWithTimestamps = $entries | Where-Object { $_.TimeCreated }
                    $eventCount = ($eventsWithTimestamps | Measure-Object).Count

                    Add-CategoryCheck -CategoryResult $result -Name 'WMI operation error events' -Status ([string]$eventCount)

                    if ($eventCount -ge 3) {
                        $latest = $eventsWithTimestamps | Sort-Object TimeCreated | Select-Object -Last 1
                        $evidence = [ordered]@{
                            Count = $eventCount
                        }

                        if ($latest -and $latest.TimeCreated) {
                            $evidence['LastUtc'] = $latest.TimeCreated.ToUniversalTime().ToString('o')
                        }

                        if ($latest -and -not [string]::IsNullOrWhiteSpace($latest.Message)) {
                            $evidence['OperationHint'] = $latest.Message
                        }

                        Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'WMI operation errors detected' -Evidence ($evidence | ConvertTo-Json -Compress) -Subcategory 'WMI Activity'
                    }
                } elseif ($entries.Error) {
                    Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Unable to read Microsoft-Windows-WMI-Activity/Operational event log, so WMI issues may be hidden.' -Evidence $entries.Error -Subcategory 'WMI Activity'
                }
            }
        }
    } else {
        Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Event log artifact missing, so noisy or unhealthy logs may be hidden.' -Subcategory 'Collection'
    }

    return $result
}
