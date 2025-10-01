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

            if ($payload.PSObject.Properties['System']) {
                $systemEntries = @($payload.System)
                $systemErrors = @($systemEntries | Where-Object { $_ -and $_.PSObject.Properties['Error'] })
                if ($systemEntries.Count -gt 0 -and $systemErrors.Count -eq 0) {
                    Write-HeuristicDebug -Source 'Events' -Message 'Analyzing System log for Netlogon/LSA issues'

                    $now = Get-Date
                    $recentThreshold = $now.AddDays(-7)
                    $windowThreshold = $now.AddDays(-14)

                    $windowEvents = New-Object System.Collections.Generic.List[pscustomobject]

                    foreach ($entry in $systemEntries) {
                        if (-not $entry) { continue }

                        $timeValue = $null
                        if ($entry.PSObject.Properties['TimeCreated']) {
                            $rawTime = $entry.TimeCreated
                            if ($rawTime -is [datetime]) {
                                $timeValue = [datetime]$rawTime
                            } else {
                                [datetime]::TryParse([string]$rawTime, [ref]$timeValue) | Out-Null
                            }
                        }

                        if (-not $timeValue) { continue }
                        if ($timeValue -lt $windowThreshold) { continue }

                        $provider = if ($entry.PSObject.Properties['ProviderName']) { [string]$entry.ProviderName } else { '' }
                        $message = if ($entry.PSObject.Properties['Message']) { [string]$entry.Message } else { '' }
                        $level = if ($entry.PSObject.Properties['LevelDisplayName']) { [string]$entry.LevelDisplayName } else { '' }
                        $eventId = if ($entry.PSObject.Properties['Id']) { $entry.Id } else { $null }

                        $isErrorLevel = ([string]::IsNullOrWhiteSpace($level) -or $level.Equals('Error', 'InvariantCultureIgnoreCase'))
                        $isNetlogon = ($eventId -eq 5719 -and $provider -and ($provider -match '(?i)netlogon'))
                        $lsaProviderMatch = ($provider -match '(?i)lsasrv' -or $provider -match '(?i)microsoft-windows-security-kerberos')
                        $messageContainsLsa = ($message -match '(?i)\bLSASRV\b')
                        $isLsa = ($isErrorLevel -and ($lsaProviderMatch -or $messageContainsLsa))

                        if (-not $isNetlogon -and -not $isLsa) { continue }

                        $windowEvents.Add([pscustomobject]@{
                            Id            = if ($eventId -ne $null) { [int]$eventId } else { $null }
                            TimeCreated   = $timeValue
                            ProviderName  = $provider
                            Level         = $level
                            Type          = if ($isNetlogon) { 'NETLOGON' } else { 'LSASRV' }
                        }) | Out-Null
                    }

                    if ($windowEvents.Count -gt 0) {
                        $recentEvents = @($windowEvents | Where-Object { $_.TimeCreated -ge $recentThreshold })
                        if ($recentEvents.Count -ge 3) {
                            $olderEvents = @($windowEvents | Where-Object { $_.TimeCreated -lt $recentThreshold })
                            $lsaEvents = @($windowEvents | Where-Object { $_.Type -eq 'LSASRV' })

                            $eventIdSet = @($recentEvents | Where-Object { $_.Id -ne $null } | ForEach-Object { $_.Id } | Sort-Object -Unique)
                            $lastEvent = $recentEvents | Sort-Object TimeCreated -Descending | Select-Object -First 1
                            $lastUtc = if ($lastEvent -and $lastEvent.TimeCreated) { $lastEvent.TimeCreated.ToUniversalTime().ToString('o') } else { $null }

                            $severity = 'medium'
                            if ($olderEvents.Count -gt 0 -and $lsaEvents.Count -gt 0) {
                                $severity = 'high'
                            }

                            $evidence = [ordered]@{
                                eventIdSet = $eventIdSet
                                count      = $recentEvents.Count
                                lastUtc    = $lastUtc
                            }

                            Add-CategoryIssue -CategoryResult $result -Severity $severity -Title 'Netlogon secure channel / domain reachability issues' -Evidence $evidence -Subcategory 'Netlogon/LSA (Domain Join)'
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
