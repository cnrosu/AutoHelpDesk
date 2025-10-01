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

            if ($payload.PSObject.Properties['StorageDiskEvents']) {
                $diskEvents = $payload.StorageDiskEvents
                $eventCount = 0
                $hasError = $false
                $hasSummary = [bool]$diskEvents
                if ($diskEvents -and $diskEvents.PSObject.Properties['Events'] -and $diskEvents.Events) {
                    $eventCount = ($diskEvents.Events | Where-Object { $_ -and $_.Count -gt 0 }).Count
                }
                if ($diskEvents -and $diskEvents.PSObject.Properties['Error'] -and $diskEvents.Error) {
                    $hasError = $true
                }

                Write-HeuristicDebug -Source 'Events' -Message 'Evaluating storage disk events' -Data ([ordered]@{
                    HasSummary = $hasSummary
                    EventSummaries = $eventCount
                    HasError = $hasError
                })

                if ($diskEvents -and $diskEvents.PSObject.Properties['Error'] -and $diskEvents.Error) {
                    Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Disk integrity event query failed, so intermittent storage faults may be hidden.' -Evidence $diskEvents.Error -Subcategory 'Storage / Disk'
                } elseif ($diskEvents -and $diskEvents.PSObject.Properties['Events']) {
                    $eventSummaries = @($diskEvents.Events | Where-Object { $_ -and $_.Count -gt 0 })
                    if ($eventSummaries.Count -gt 0) {
                        $hasNtfs55 = $eventSummaries | Where-Object { $_.EventId -eq 55 -and $_.Count -gt 0 }
                        $severity = if ($hasNtfs55) { 'high' } else { 'medium' }

                        Write-HeuristicDebug -Source 'Events' -Message 'Disk/NTFS integrity events detected' -Data ([ordered]@{
                            Severity = $severity
                            Entries = $eventSummaries.Count
                            HasNtfs55 = [bool]$hasNtfs55
                        })

                        $evidenceLines = @()
                        if ($diskEvents.PSObject.Properties['WindowStartUtc'] -and $diskEvents.WindowStartUtc) {
                            $evidenceLines += ('WindowStartUtc {0}' -f $diskEvents.WindowStartUtc)
                        }

                        foreach ($entry in ($eventSummaries | Sort-Object -Property { [int]$_.EventId })) {
                            $parts = @('EventId {0}' -f $entry.EventId, 'Count {0}' -f $entry.Count)

                            if ($entry.PSObject.Properties['Provider'] -and $entry.Provider) {
                                $parts += ('Provider {0}' -f $entry.Provider)
                            }

                            if ($entry.PSObject.Properties['LastUtc'] -and $entry.LastUtc) {
                                $parts += ('LastUtc {0}' -f $entry.LastUtc)
                            }

                            $deviceHints = @()
                            if ($entry.PSObject.Properties['DeviceHints'] -and $entry.DeviceHints) {
                                if ($entry.DeviceHints -is [System.Collections.IEnumerable] -and -not ($entry.DeviceHints -is [string])) {
                                    foreach ($hint in $entry.DeviceHints) {
                                        if ($hint) { $deviceHints += [string]$hint }
                                    }
                                } else {
                                    $deviceHints = @([string]$entry.DeviceHints)
                                }
                            } elseif ($entry.PSObject.Properties['DeviceHint'] -and $entry.DeviceHint) {
                                $deviceHints = @([string]$entry.DeviceHint)
                            }

                            if ($deviceHints.Count -gt 0) {
                                $parts += ('Devices {0}' -f (($deviceHints | Sort-Object -Unique) -join ', '))
                            }

                            $evidenceLines += ($parts -join '; ')
                        }

                        Add-CategoryIssue -CategoryResult $result -Severity $severity -Title 'Disk I/O or NTFS integrity issues detected' -Evidence ($evidenceLines -join "`n") -Subcategory 'Storage / Disk'
                    }
                }
            }
        }
    } else {
        Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Event log artifact missing, so noisy or unhealthy logs may be hidden.' -Subcategory 'Collection'
    }

    return $result
}
