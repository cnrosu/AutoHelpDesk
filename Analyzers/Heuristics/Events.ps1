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

    if ($payload -and $payload.PSObject.Properties['UserProfileService']) {
        $userProfile = $payload.UserProfileService
        $rawEvents = @()
        if ($userProfile -and $userProfile.PSObject.Properties['Events']) {
            $rawEvents = @($userProfile.Events)
        }

        $eventCount = $rawEvents.Count
        $logName = if ($userProfile -and $userProfile.PSObject.Properties['LogName']) { [string]$userProfile.LogName } else { 'Unknown' }
        Add-CategoryCheck -CategoryResult $result -Name 'User profile events (14d)' -Status ([string]$eventCount) -Details ("Log: {0}" -f $logName)

        $parsedEvents = [System.Collections.Generic.List[pscustomobject]]::new()
        foreach ($evt in $rawEvents) {
            if (-not $evt) { continue }

            $id = $null
            if ($evt.PSObject.Properties['Id'] -and $evt.Id) {
                try { $id = [int]$evt.Id } catch { $id = $null }
            }

            $timeUtc = $null
            if ($evt.PSObject.Properties['TimeCreated'] -and $evt.TimeCreated) {
                $rawTime = $evt.TimeCreated
                if ($rawTime -is [datetime]) {
                    try { $timeUtc = $rawTime.ToUniversalTime() } catch { $timeUtc = $rawTime }
                } elseif ($rawTime -is [string]) {
                    try {
                        $parsed = [datetime]::Parse($rawTime)
                        $timeUtc = $parsed.ToUniversalTime()
                    } catch {
                    }
                }
            }

            $sidTail = $null
            if ($evt.PSObject.Properties['SidTail']) { $sidTail = [string]$evt.SidTail }

            $profilePath = $null
            if ($evt.PSObject.Properties['ProfilePath']) { $profilePath = [string]$evt.ProfilePath }

            $recordId = $null
            if ($evt.PSObject.Properties['RecordId']) { $recordId = $evt.RecordId }

            $parsedEvents.Add([pscustomobject]@{
                Id          = $id
                TimeUtc     = $timeUtc
                SidTail     = $sidTail
                ProfilePath = $profilePath
                RecordId    = $recordId
            }) | Out-Null
        }

        $nowUtc = (Get-Date).ToUniversalTime()
        $sevenDaysAgo = $nowUtc.AddDays(-7)
        $fourteenDaysAgo = $nowUtc.AddDays(-14)
        $tempProfileIds = @(1511, 1515)
        $trackedEventIds = @(1511, 1515, 1518, 1530, 1533)

        $recentTempProfiles = $parsedEvents | Where-Object { $_.Id -in $tempProfileIds -and (-not $_.TimeUtc -or $_.TimeUtc -ge $sevenDaysAgo) }
        if ($recentTempProfiles.Count -gt 0) {
            $aggregated = @{}
            $index = 0
            foreach ($entry in $recentTempProfiles) {
                $keyParts = [System.Collections.Generic.List[string]]::new()
                if ($entry.SidTail) { $null = $keyParts.Add(('sid:{0}' -f $entry.SidTail)) }
                if ($entry.ProfilePath) { $null = $keyParts.Add(('path:{0}' -f $entry.ProfilePath)) }
                if ($keyParts.Count -eq 0) {
                    if ($entry.RecordId) {
                        $null = $keyParts.Add(('record:{0}' -f $entry.RecordId))
                    } elseif ($entry.TimeUtc) {
                        $null = $keyParts.Add(('time:{0:O}' -f $entry.TimeUtc))
                    } else {
                        $null = $keyParts.Add(('index:{0}' -f $index))
                    }
                }

                $key = ($keyParts -join '|')
                if (-not $aggregated.ContainsKey($key)) {
                    $aggregated[$key] = [ordered]@{
                        SidTail     = $entry.SidTail
                        ProfilePath = $entry.ProfilePath
                        LastUtc     = $entry.TimeUtc
                    }
                } else {
                    if (-not $aggregated[$key].SidTail -and $entry.SidTail) { $aggregated[$key].SidTail = $entry.SidTail }
                    if (-not $aggregated[$key].ProfilePath -and $entry.ProfilePath) { $aggregated[$key].ProfilePath = $entry.ProfilePath }
                    if ($entry.TimeUtc -and ($null -eq $aggregated[$key].LastUtc -or $entry.TimeUtc -gt $aggregated[$key].LastUtc)) {
                        $aggregated[$key].LastUtc = $entry.TimeUtc
                    }
                }

                $index++
            }

            $evidenceLines = [System.Collections.Generic.List[string]]::new()
            foreach ($aggregateEntry in $aggregated.GetEnumerator()) {
                $details = $aggregateEntry.Value
                $parts = [System.Collections.Generic.List[string]]::new()
                if ($details.SidTail) { $null = $parts.Add(('sidTail={0}' -f $details.SidTail)) }
                if ($details.ProfilePath) { $null = $parts.Add(('profilePath={0}' -f $details.ProfilePath)) }
                if ($details.LastUtc) { $null = $parts.Add(('lastUtc={0}' -f $details.LastUtc.ToString('u'))) }
                if ($parts.Count -eq 0) { $null = $parts.Add('details=unavailable') }
                $null = $evidenceLines.Add($parts -join '; ')
            }

            $evidence = if ($evidenceLines.Count -gt 0) { $evidenceLines -join "`n" } else { 'No additional evidence captured.' }
            Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Temporary profile loaded' -Evidence $evidence -Subcategory 'User Profile'
        }

        $profileEntries = @()
        $profileListError = $null
        if ($userProfile -and $userProfile.PSObject.Properties['ProfileList']) {
            $profileList = $userProfile.ProfileList
            if ($profileList -and $profileList.PSObject.Properties['Entries']) {
                $profileEntries = @($profileList.Entries)
            }
            if ($profileList -and $profileList.PSObject.Properties['Error']) {
                $profileListError = $profileList.Error
            }
        }

        $abnormalStates = [System.Collections.Generic.List[object]]::new()
        foreach ($profile in $profileEntries) {
            if (-not $profile) { continue }
            if (-not $profile.PSObject.Properties['State']) { continue }
            $rawState = $profile.State
            if ($null -eq $rawState) { continue }
            $stateValue = $null
            try {
                $stateValue = [int]$rawState
            } catch {
                continue
            }
            if ($stateValue -ne 0) {
                $abnormalStates.Add($profile) | Out-Null
            }
        }

        $recentTrackedEvents = $parsedEvents | Where-Object { $_.Id -in $trackedEventIds -and $_.TimeUtc -and $_.TimeUtc -ge $fourteenDaysAgo }

        if (-not $profileListError -and $profileEntries.Count -gt 0 -and $abnormalStates.Count -eq 0 -and $recentTrackedEvents.Count -eq 0 -and $recentTempProfiles.Count -eq 0) {
            Add-CategoryNormal -CategoryResult $result -Title 'Profiles healthy — no 1511/1515/1518/1530/1533 in last 14 days and ProfileList states normal.' -Subcategory 'User Profile'
        }

        if ($profileListError) {
            Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'ProfileList registry capture failed, so profile health is unknown.' -Evidence $profileListError -Subcategory 'User Profile'
        }
    }

    return $result
}
