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
        }
    } else {
        Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Event log artifact missing, so noisy or unhealthy logs may be hidden.' -Subcategory 'Collection'
    }

    $userProfileArtifact = Get-AnalyzerArtifact -Context $Context -Name 'user-profile-events'
    Write-HeuristicDebug -Source 'Events' -Message 'Resolved user profile events artifact' -Data ([ordered]@{
        Found = [bool]$userProfileArtifact
    })
    if ($userProfileArtifact) {
        $userProfilePayload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $userProfileArtifact)
        Write-HeuristicDebug -Source 'Events' -Message 'Evaluating user profile payload' -Data ([ordered]@{
            HasPayload = [bool]$userProfilePayload
        })
        if ($userProfilePayload -and $userProfilePayload.PSObject.Properties['Events']) {
            $rawEvents = Ensure-Array $userProfilePayload.Events
            if ($rawEvents.Count -eq 1 -and $rawEvents[0].PSObject.Properties['Error']) {
                Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'User Profile Service events unavailable, so profile unload conflicts may be hidden.' -Evidence $rawEvents[0].Error -Subcategory 'User Profile (Roaming/Registry)'
            } else {
                $events = $rawEvents | Where-Object { $_ -and $_.PSObject.Properties['Id'] }
                if ($events -and $events.Count -gt 0) {
                    $now = Get-Date
                    $cutoff7 = $now.AddDays(-7)
                    $cutoff14 = $now.AddDays(-14)

                    $eventWrappers = foreach ($entry in $events) {
                        $timestamp = $null
                        if ($entry.TimeCreated) {
                            $timestamp = ConvertFrom-Iso8601 $entry.TimeCreated
                            if (-not $timestamp) {
                                try {
                                    $timestamp = [datetime]::Parse($entry.TimeCreated)
                                } catch {
                                    $timestamp = $null
                                }
                            }
                        }

                        [pscustomobject]@{
                            Event = $entry
                            Time  = $timestamp
                        }
                    }

                    $recent7 = @($eventWrappers | Where-Object { $_.Time -and $_.Time -ge $cutoff7 })
                    $recent14 = @($eventWrappers | Where-Object { $_.Time -and $_.Time -ge $cutoff14 })

                    Write-HeuristicDebug -Source 'Events' -Message 'User profile event counts calculated' -Data ([ordered]@{
                        Total    = $events.Count
                        Recent7  = $recent7.Count
                        Recent14 = $recent14.Count
                    })

                    if ($recent7.Count -ge 3 -and $recent14.Count -gt 1) {
                        $latest = $recent7 | Sort-Object -Property Time -Descending | Select-Object -First 1
                        $latestTime = if ($latest -and $latest.Time) { $latest.Time } else { $null }
                        $lastUtc = if ($latestTime) { $latestTime.ToUniversalTime().ToString('o') } else { $null }
                        $messageHint = $null
                        if ($latest -and $latest.Event -and $latest.Event.Message) {
                            $messageHint = Get-TopLines -Text $latest.Event.Message -Count 20
                        }

                        $evidence = [ordered]@{
                            Count       = [int]$recent7.Count
                            LastUtc     = $lastUtc
                            MessageHint = $messageHint
                            Advice      = 'Enable the "Verbose vs normal status messages" GPO to collect more detailed profile unload logging.'
                        }

                        Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Profile unload conflicts detected' -Evidence $evidence -Subcategory 'User Profile (Roaming/Registry)'
                    }
                }
            }
        }
    }

    return $result
}
