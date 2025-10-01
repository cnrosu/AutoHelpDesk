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

            if ($payload.PSObject.Properties['WheaLogger']) {
                Write-HeuristicDebug -Source 'Events' -Message 'Inspecting WHEA logger entries'
                $wheaData = $payload.WheaLogger

                if ($wheaData -and $wheaData.PSObject.Properties['Error'] -and $wheaData.Error) {
                    Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Unable to read WHEA hardware event log, so corrected error history may be incomplete.' -Evidence $wheaData.Error -Subcategory 'Hardware / WHEA'
                } else {
                    $wheaEvents = @()
                    if ($wheaData -and $wheaData.PSObject.Properties['Events']) {
                        $wheaEvents = @($wheaData.Events) | Where-Object { $_ }
                    } elseif ($wheaData) {
                        $wheaEvents = @($wheaData) | Where-Object { $_ }
                    }

                    if ($wheaEvents) {
                        $correctedEvents = @($wheaEvents | Where-Object { $_.Id -in @(17, 19) })
                        $totalCorrected = $correctedEvents.Count
                        Write-HeuristicDebug -Source 'Events' -Message 'Evaluated WHEA corrected hardware errors' -Data ([ordered]@{
                            Count = $totalCorrected
                        })

                        if ($totalCorrected -gt 0) {
                            $latestEvent = $correctedEvents | Sort-Object -Property TimeCreated -Descending | Select-Object -First 1
                            $severity = 'medium'
                            if ($totalCorrected -eq 1 -and $latestEvent -and $latestEvent.Id -eq 17) {
                                $severity = 'low'
                            }

                            $lastUtc = $null
                            if ($latestEvent) {
                                if ($latestEvent.PSObject.Properties['TimeCreatedUtc'] -and $latestEvent.TimeCreatedUtc) {
                                    $lastUtc = $latestEvent.TimeCreatedUtc
                                } elseif ($latestEvent.TimeCreated) {
                                    try {
                                        $lastUtc = $latestEvent.TimeCreated.ToUniversalTime()
                                    } catch {
                                    }
                                }
                            }

                            $deviceBus = $null
                            if ($latestEvent -and $latestEvent.Message) {
                                $lines = @($latestEvent.Message -split "`r?`n") | ForEach-Object { $_.Trim() } | Where-Object { $_ }
                                $busLine = $lines | Where-Object { $_ -match 'Bus:Device:Function' } | Select-Object -First 1
                                if (-not $busLine) {
                                    $busLine = $lines | Where-Object { $_ -like 'Device:*' } | Select-Object -First 1
                                }
                                if ($busLine) {
                                    $parts = $busLine -split ':', 2
                                    if ($parts.Count -ge 2 -and $parts[1]) {
                                        $deviceBus = $parts[1].Trim()
                                    } else {
                                        $deviceBus = $busLine
                                    }
                                }
                            }

                            $evidence = [ordered]@{
                                Count   = $totalCorrected
                                LastUtc = if ($lastUtc) { $lastUtc.ToString('o') } else { $null }
                            }
                            if ($deviceBus) {
                                $evidence['DeviceBus'] = $deviceBus
                            }

                            Add-CategoryIssue -CategoryResult $result -Severity $severity -Title 'Corrected hardware errors reported (WHEA)' -Evidence $evidence -Subcategory 'Hardware / WHEA'
                        }
                    }
                }
            }
        }
    } else {
        Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Event log artifact missing, so noisy or unhealthy logs may be hidden.' -Subcategory 'Collection'
    }

    return $result
}
