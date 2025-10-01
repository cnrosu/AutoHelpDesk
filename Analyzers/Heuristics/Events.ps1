<#!
.SYNOPSIS
    Event log heuristics summarizing recent error and warning volume.
#>

. (Join-Path -Path (Split-Path $PSScriptRoot -Parent) -ChildPath 'AnalyzerCommon.ps1')

function Get-VssEventHint {
    param(
        [string]$Message
    )

    if ([string]::IsNullOrWhiteSpace($Message)) { return $null }

    $maxLength = 200
    $patterns = @(
        '(?im)^\s*Writer\s+Name\s*:\s*(?<value>.+)$',
        '(?im)^\s*COM error.*$',
        '(?im)^\s*hr\s*=\s*0x[0-9a-f]+.*$'
    )

    foreach ($pattern in $patterns) {
        $match = [regex]::Match($Message, $pattern)
        if ($match.Success) {
            $text = if ($match.Groups['value'] -and $match.Groups['value'].Success) {
                'Writer Name: ' + $match.Groups['value'].Value.Trim()
            } else {
                $match.Value.Trim()
            }

            if ($text.Length -gt $maxLength) { $text = $text.Substring(0, $maxLength) }
            return $text
        }
    }

    $hrMatch = [regex]::Match($Message, '(?i)hr\s*=\s*0x[0-9a-f]+')
    if ($hrMatch.Success) {
        $start = $hrMatch.Index
        $length = [Math]::Min($Message.Length - $start, $maxLength)
        $snippet = $Message.Substring($start, $length).Trim()
        if ($snippet.Length -gt $maxLength) { $snippet = $snippet.Substring(0, $maxLength) }
        return $snippet
    }

    return $null
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
            $vssEventIds = @(8193, 12289)
            $vssWindowStart = (Get-Date).ToUniversalTime().AddDays(-7)
            $vssEventCount = 0
            $vssLatestTime = $null
            $vssEventIdSet = [System.Collections.Generic.HashSet[int]]::new()
            $vssWriterHint = $null

            foreach ($logName in @('System','Application','GroupPolicy')) {
                Write-HeuristicDebug -Source 'Events' -Message ('Inspecting {0} log entries' -f $logName)
                if (-not $payload.PSObject.Properties[$logName]) { continue }
                $entriesSource = $payload.$logName
                if ($entriesSource -and -not $entriesSource.Error) {
                    $entries = if ($entriesSource -is [System.Collections.IEnumerable] -and -not ($entriesSource -is [string])) {
                        @($entriesSource)
                    } else {
                        @($entriesSource)
                    }
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

                    if ($logName -in @('System','Application')) {
                        foreach ($entry in $entries) {
                            if (-not $entry) { continue }
                            if (-not $entry.PSObject.Properties['Id']) { continue }
                            $eventId = $null
                            try {
                                $eventId = [int]$entry.Id
                            } catch {
                                continue
                            }

                            if ($vssEventIds -notcontains $eventId) { continue }

                            $eventTime = $null
                            if ($entry.PSObject.Properties['TimeCreated'] -and $entry.TimeCreated) {
                                try {
                                    $eventTime = [datetime]$entry.TimeCreated
                                } catch {
                                    $eventTime = $null
                                }
                            }
                            if (-not $eventTime) { continue }

                            $eventTimeUtc = $eventTime.ToUniversalTime()
                            if ($eventTimeUtc -lt $vssWindowStart) { continue }

                            $vssEventCount++
                            $null = $vssEventIdSet.Add($eventId)
                            if (-not $vssLatestTime -or $eventTimeUtc -gt $vssLatestTime) { $vssLatestTime = $eventTimeUtc }

                            if (-not $vssWriterHint -and $entry.PSObject.Properties['Message'] -and $entry.Message) {
                                $hint = Get-VssEventHint -Message ([string]$entry.Message)
                                if ($hint) { $vssWriterHint = $hint }
                            }
                        }
                    }
                } elseif ($entriesSource.Error) {
                    $logSubcategory = ("{0} Event Log" -f $logName)
                    Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title ("Unable to read {0} event log, so noisy or unhealthy logs may be hidden." -f $logName) -Evidence $entriesSource.Error -Subcategory $logSubcategory
                }
            }

            Write-HeuristicDebug -Source 'Events' -Message 'Evaluated VSS event activity' -Data ([ordered]@{
                Count    = $vssEventCount
                LatestUtc = if ($vssLatestTime) { $vssLatestTime.ToString('o') } else { '<none>' }
            })

            if ($vssEventCount -ge 2) {
                $evidence = [ordered]@{
                    eventIdSet = @($vssEventIdSet.ToArray() | Sort-Object)
                    count      = $vssEventCount
                }

                if ($vssWriterHint) { $evidence['writerHint'] = $vssWriterHint }
                if ($vssLatestTime) { $evidence['lastUtc'] = $vssLatestTime.ToString('o') }

                Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'VSS errors impacting backups' -Evidence ([pscustomobject]$evidence) -Subcategory 'VSS (Backup/Restore)'
            }
        }
    } else {
        Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Event log artifact missing, so noisy or unhealthy logs may be hidden.' -Subcategory 'Collection'
    }

    return $result
}
