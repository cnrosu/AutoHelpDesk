<#!
.SYNOPSIS
    Validates Windows push notification services and scheduled tasks required for Intune quick sync triggers.
#>

function Invoke-IntuneHeuristic-PushNotificationQuickSync {
    param(
        [Parameter(Mandatory)]
        $Context,

        [Parameter(Mandatory)]
        $Result
    )

    Write-HeuristicDebug -Source 'Intune/PushNotificationQuickSync' -Message 'Evaluating push notification quick sync signals'

    $serviceStatus = Get-IntunePushNotificationServiceStatus -Context $Context
    $taskStatus = Get-IntunePushLaunchTaskStatus -Context $Context
    $collectorPayload = Get-IntunePushCollectorPayload -Context $Context

    $serviceCollected = ($serviceStatus -and $serviceStatus.Collected)
    $taskCollected = ($taskStatus -and $taskStatus.Collected)
    $serviceFound = ($serviceStatus -and $serviceStatus.Found)

    $startModeNormalized = if ($serviceStatus) { $serviceStatus.StartModeNormalized } else { $null }
    if (-not $startModeNormalized) { $startModeNormalized = 'unknown' }

    $startTypeKnown = ($startModeNormalized -ne 'unknown' -and $startModeNormalized -ne $null)
    $startTypeOk = $false
    if ($startTypeKnown) { $startTypeOk = ($startModeNormalized -in @('automatic','automatic-delayed')) }

    $serviceManual = ($startModeNormalized -eq 'manual')
    $serviceDisabled = ($startModeNormalized -eq 'disabled')

    $serviceStartTypeText = if ($serviceStatus -and $serviceStatus.StartMode) { [string]$serviceStatus.StartMode } else { $null }
    if (-not $serviceStartTypeText) {
        switch ($startModeNormalized) {
            'automatic' { $serviceStartTypeText = 'Automatic'; break }
            'automatic-delayed' { $serviceStartTypeText = 'AutomaticDelayedStart'; break }
            'manual' { $serviceStartTypeText = 'Manual'; break }
            'disabled' { $serviceStartTypeText = 'Disabled'; break }
            default { $serviceStartTypeText = 'Unknown'; break }
        }
    }

    $serviceStateText = 'Unknown'
    if ($serviceStatus) {
        if ($serviceStatus.State) { $serviceStateText = [string]$serviceStatus.State }
        elseif ($serviceStatus.Status) { $serviceStateText = [string]$serviceStatus.Status }
    }
    if (-not $serviceStateText) { $serviceStateText = 'Unknown' }

    $taskFound = ($taskStatus -and $taskStatus.Found)
    $taskEnabled = if ($taskStatus) { $taskStatus.Enabled } else { $null }
    $taskEnabledText = if ($null -eq $taskEnabled) { 'Unknown' } elseif ($taskEnabled) { 'True' } else { 'False' }

    $taskStateText = 'Unknown'
    if ($taskStatus) {
        if ($taskStatus.Status) { $taskStateText = [string]$taskStatus.Status }
        elseif ($taskStatus.ScheduledTaskState) { $taskStateText = [string]$taskStatus.ScheduledTaskState }
    }

    $lastResultRaw = if ($taskStatus -and $taskStatus.LastResult) { [string]$taskStatus.LastResult } else { 'Unknown' }
    $lastResultNormalized = if ($taskStatus) { $taskStatus.LastResultNormalized } else { 'unknown' }

    $lastRunUtc = $null
    if ($taskStatus -and $taskStatus.LastRunTimeUtcDateTime) {
        $lastRunUtc = $taskStatus.LastRunTimeUtcDateTime
    } elseif ($taskStatus -and $taskStatus.LastRunTimeUtc) {
        $lastRunUtc = ConvertTo-IntuneUtcDateTime -Value $taskStatus.LastRunTimeUtc
    } elseif ($taskStatus -and $taskStatus.LastRunTime) {
        $lastRunUtc = ConvertTo-IntuneUtcDateTime -Value $taskStatus.LastRunTime
    }

    $lastRunText = 'unknown'
    if ($taskStatus) {
        if ($taskStatus.LastRunTimeUtc) { $lastRunText = [string]$taskStatus.LastRunTimeUtc }
        elseif ($taskStatus.LastRunTime) { $lastRunText = [string]$taskStatus.LastRunTime }
    }
    if (-not $lastRunText) { $lastRunText = 'unknown' }

    $recencyWindowDays = 7
    if ($taskStatus -and $taskStatus.RecencyWindowDays) {
        try { $recencyWindowDays = [int]$taskStatus.RecencyWindowDays } catch { $recencyWindowDays = $taskStatus.RecencyWindowDays }
    } elseif ($collectorPayload -and $collectorPayload.PSObject.Properties['RecencyWindowDays']) {
        try { $recencyWindowDays = [int]$collectorPayload.RecencyWindowDays } catch { $recencyWindowDays = $collectorPayload.RecencyWindowDays }
    }
    if ($recencyWindowDays -lt 1) { $recencyWindowDays = 7 }

    $nowUtc = [datetime]::UtcNow
    $windowStartUtc = $nowUtc.AddDays(-1 * $recencyWindowDays)
    $lastRunRecent = ($lastRunUtc -and $lastRunUtc -ge $windowStartUtc)

    $taskHealthy = ($taskFound -and ($taskEnabled -ne $false) -and ($lastResultNormalized -eq 'success') -and $lastRunRecent)
    $hadRecentSuccess = ($taskFound -and ($lastResultNormalized -eq 'success') -and $lastRunRecent)

    $logsData = if ($collectorPayload -and $collectorPayload.PSObject.Properties['Logs']) { $collectorPayload.Logs } else { $null }
    $logsAvailable = ($null -ne $logsData)
    $recentErrorCount = 0
    $lastErrorUtcValue = $null
    if ($logsAvailable) {
        foreach ($logEntry in @($logsData.Push, $logsData.DMEDP)) {
            if (-not $logEntry) { continue }
            if ($logEntry.PSObject.Properties['RecentErrors']) {
                $errorsValue = $logEntry.RecentErrors
                try { $recentErrorCount += [int]$errorsValue } catch {
                    $intParsed = 0
                    if ([int]::TryParse([string]$errorsValue, [ref]$intParsed)) { $recentErrorCount += $intParsed }
                }
            }
            if ($logEntry.PSObject.Properties['LastErrorUtc'] -and $logEntry.LastErrorUtc) {
                $candidate = ConvertTo-IntuneUtcDateTime -Value $logEntry.LastErrorUtc
                if ($candidate) {
                    if (-not $lastErrorUtcValue -or $candidate -gt $lastErrorUtcValue) { $lastErrorUtcValue = $candidate }
                }
            }
        }
    }

    $recentPushErrors = ($logsAvailable -and $recentErrorCount -gt 0)
    $recentErrorsText = if ($logsAvailable) { [string]$recentErrorCount } else { 'not collected' }
    if ($logsAvailable -and $recentErrorCount -eq 0) { $recentErrorsText = '0' }

    $lastErrorUtcText = if ($lastErrorUtcValue) { $lastErrorUtcValue.ToString('yyyy-MM-ddTHH:mm:ssZ') } else { $null }

    $collectedAtText = $null
    if ($taskStatus -and $taskStatus.CollectedAtUtc) { $collectedAtText = [string]$taskStatus.CollectedAtUtc }
    elseif ($serviceStatus -and $serviceStatus.CollectedAtUtc) { $collectedAtText = [string]$serviceStatus.CollectedAtUtc }
    elseif ($collectorPayload -and $collectorPayload.PSObject.Properties['CollectedAtUtc']) { $collectedAtText = [string]$collectorPayload.CollectedAtUtc }

    $debugData = [ordered]@{
        ServiceCollected     = $serviceCollected
        ServiceFound         = $serviceFound
        ServiceStart         = $startModeNormalized
        TaskCollected        = $taskCollected
        TaskFound            = $taskFound
        TaskEnabled          = $taskEnabled
        TaskLastResult       = $lastResultNormalized
        TaskLastRunRecent    = $lastRunRecent
        RecencyWindowDays    = $recencyWindowDays
        RecentPushErrorCount = if ($logsAvailable) { $recentErrorCount } else { 'n/a' }
    }
    Write-HeuristicDebug -Source 'Intune/PushNotificationQuickSync' -Message 'Push notification dependency summary' -Data $debugData

    $dataGaps = New-Object System.Collections.Generic.List[string]
    if (-not $serviceCollected) {
        $gap = 'Intune diagnostics were incomplete, so Windows push notification service status was unavailable.'
        if ($serviceStatus -and $serviceStatus.Errors -and $serviceStatus.Errors.Count -gt 0) {
            $gap += ' (' + (($serviceStatus.Errors | Where-Object { $_ }) -join '; ') + ')'
        }
        $dataGaps.Add($gap) | Out-Null
    }
    if (-not $taskCollected) {
        $gap = 'Intune diagnostics were incomplete, so the PushLaunch scheduled task state was unavailable.'
        if ($taskStatus -and $taskStatus.Errors -and $taskStatus.Errors.Count -gt 0) {
            $gap += ' (' + (($taskStatus.Errors | Where-Object { $_ }) -join '; ') + ')'
        }
        $dataGaps.Add($gap) | Out-Null
    }
    if (-not $logsAvailable) {
        $dataGaps.Add('Push/DMEDP logs were unavailable, so push notification error history is unknown.') | Out-Null
    }

    $evidenceLines = [System.Collections.Generic.List[string]]::new()
    $serviceEvidenceParts = [System.Collections.Generic.List[string]]::new()
    $serviceEvidenceParts.Add('Found=' + [string]$serviceFound) | Out-Null
    $serviceEvidenceParts.Add('StartType=' + $serviceStartTypeText) | Out-Null
    $serviceEvidenceParts.Add('State=' + $serviceStateText) | Out-Null
    if ($serviceStatus -and $serviceStatus.Errors -and $serviceStatus.Errors.Count -gt 0) {
        $serviceEvidenceParts.Add('Errors=' + (($serviceStatus.Errors | Where-Object { $_ }) -join ' | ')) | Out-Null
    }
    $evidenceLines.Add('Service: dmwappushservice → ' + ($serviceEvidenceParts -join '; ')) | Out-Null

    $taskEvidenceParts = [System.Collections.Generic.List[string]]::new()
    $taskEvidenceParts.Add('Exists=' + [string]$taskFound) | Out-Null
    $taskEvidenceParts.Add('Enabled=' + $taskEnabledText) | Out-Null
    $taskEvidenceParts.Add('State=' + $taskStateText) | Out-Null
    $taskEvidenceParts.Add('LastResult=' + $lastResultRaw) | Out-Null
    $taskEvidenceParts.Add('LastRun=' + $lastRunText) | Out-Null
    if ($taskStatus -and $taskStatus.Errors -and $taskStatus.Errors.Count -gt 0) {
        $taskEvidenceParts.Add('Errors=' + (($taskStatus.Errors | Where-Object { $_ }) -join ' | ')) | Out-Null
    }
    $evidenceLines.Add('Task: \\Microsoft\\Windows\\PushToInstall\\PushLaunch → ' + ($taskEvidenceParts -join '; ')) | Out-Null

    if ($logsAvailable) {
        $logParts = [System.Collections.Generic.List[string]]::new()
        $logParts.Add('Errors=' + $recentErrorsText) | Out-Null
        if ($lastErrorUtcText) { $logParts.Add('LastErrorUtc=' + $lastErrorUtcText) | Out-Null }
        $evidenceLines.Add('Logs: ' + ($logParts -join '; ')) | Out-Null
    } else {
        $evidenceLines.Add('Logs: not collected') | Out-Null
    }
    $evidenceLines.Add('RecencyWindowDays: ' + [string]$recencyWindowDays) | Out-Null
    if ($collectedAtText) { $evidenceLines.Add('CollectedAtUtc: ' + $collectedAtText) | Out-Null }

    $healthyTitle = 'Intune push wake is healthy: StartType={0}; Task.Enabled={1}; LastResult={2}; LastRun={3}; RecentErrors={4}.' -f $serviceStartTypeText, $taskEnabledText, $lastResultRaw, $lastRunText, $recentErrorsText

    if ($startTypeOk -and $taskHealthy -and -not $recentPushErrors) {
        Add-CategoryNormal -CategoryResult $Result -Title $healthyTitle -Evidence $evidenceLines -Subcategory 'Enrollment & Connectivity'
        if ($dataGaps.Count -gt 0) {
            foreach ($gap in $dataGaps) {
                $gapExplanation = 'Push wake is unverified: StartType={0}; Task.Enabled={1}; LastResult={2}; LastRun={3}; RecentErrors={4}.' -f $serviceStartTypeText, $taskEnabledText, $lastResultRaw, $lastRunText, $recentErrorsText
                Add-CategoryIssue -CategoryResult $Result -Severity 'info' -Title $gap -Subcategory 'Enrollment & Connectivity' -Explanation $gapExplanation
            }
        }
        return
    }

    $staleWindowStart = $windowStartUtc.AddDays(-7)
    $staleButRecent = ($startTypeOk -and $taskFound -and ($taskEnabled -ne $false) -and ($lastResultNormalized -eq 'success') -and $lastRunUtc -and $lastRunUtc -lt $windowStartUtc -and $lastRunUtc -ge $staleWindowStart -and -not $recentPushErrors)

    if ($staleButRecent) {
        $title = 'Intune/Push Wake: PushLaunch run slightly older than {0} days → Info' -f $recencyWindowDays
        $explanation = 'Push wake is misconfigured: StartType={0}; Task.Enabled={1}; LastResult={2}; LastRun={3}; RecentErrors={4}.' -f $serviceStartTypeText, $taskEnabledText, $lastResultRaw, $lastRunText, $recentErrorsText
        Add-CategoryIssue -CategoryResult $Result -Severity 'info' -Title $title -Evidence $evidenceLines -Subcategory 'Enrollment & Connectivity' -Explanation $explanation
        if ($dataGaps.Count -gt 0) {
            foreach ($gap in $dataGaps) {
                $gapExplanation = 'Push wake is unverified: StartType={0}; Task.Enabled={1}; LastResult={2}; LastRun={3}; RecentErrors={4}.' -f $serviceStartTypeText, $taskEnabledText, $lastResultRaw, $lastRunText, $recentErrorsText
                Add-CategoryIssue -CategoryResult $Result -Severity 'info' -Title $gap -Subcategory 'Enrollment & Connectivity' -Explanation $gapExplanation
            }
        }
        return
    }

    $reasons = New-Object System.Collections.Generic.List[string]
    if (-not $serviceFound) {
        $reasons.Add('Windows Push Notification Service is missing') | Out-Null
    } elseif ($serviceDisabled) {
        $reasons.Add('Windows Push Notification Service is disabled') | Out-Null
    } elseif ($serviceManual -and -not $taskHealthy) {
        $reasons.Add('Windows Push Notification Service is set to Manual start') | Out-Null
    } elseif ($startTypeKnown -and -not $startTypeOk) {
        $reasons.Add("Windows Push Notification Service start type is $serviceStartTypeText") | Out-Null
    }

    if (-not $taskFound) {
        $reasons.Add('PushLaunch scheduled task is missing') | Out-Null
    } else {
        if ($taskEnabled -eq $false) {
            $reasons.Add('PushLaunch scheduled task is disabled') | Out-Null
        }
        if ($lastResultNormalized -eq 'failure') {
            $reasons.Add("PushLaunch last run failed (LastResult=$lastResultRaw)") | Out-Null
        }
        if (-not $hadRecentSuccess) {
            $reasons.Add('no successful PushLaunch run in last ' + [string]$recencyWindowDays + ' days') | Out-Null
        }
    }

    if ($recentPushErrors) {
        $reasons.Add('recent push notification errors detected') | Out-Null
    }

    $severity = $null
    if (-not $serviceFound) {
        $severity = 'high'
    } elseif ($serviceDisabled) {
        $severity = 'high'
    } elseif (-not $taskFound) {
        $severity = 'high'
    } elseif (($taskEnabled -eq $false) -and (-not $hadRecentSuccess)) {
        $severity = 'high'
    } elseif ($recentPushErrors -and -not $taskHealthy) {
        $severity = 'high'
    } elseif ($serviceManual -and -not $taskHealthy) {
        $severity = 'medium'
    } elseif ($startTypeKnown -and -not $startTypeOk -and -not $taskHealthy) {
        $severity = 'high'
    } elseif (-not $taskHealthy) {
        $severity = 'medium'
    } elseif ($recentPushErrors) {
        $severity = 'medium'
    }

    if (-not $severity -and $reasons.Count -gt 0) {
        $severity = 'medium'
    }

    if (-not $severity -and $dataGaps.Count -gt 0) {
        foreach ($gap in $dataGaps) {
            $gapExplanation = 'Push wake is unverified: StartType={0}; Task.Enabled={1}; LastResult={2}; LastRun={3}; RecentErrors={4}.' -f $serviceStartTypeText, $taskEnabledText, $lastResultRaw, $lastRunText, $recentErrorsText
            Add-CategoryIssue -CategoryResult $Result -Severity 'info' -Title $gap -Subcategory 'Enrollment & Connectivity' -Explanation $gapExplanation
        }
        return
    }

    if (-not $severity) { return }

    $severityLabelMap = @{ high = 'High'; medium = 'Medium'; info = 'Info' }
    $severityLabel = if ($severityLabelMap.ContainsKey($severity)) { $severityLabelMap[$severity] } else { 'Info' }

    $titleReason = if ($reasons.Count -gt 0) { $reasons -join ' and ' } else { 'push wake state is unknown' }
    $title = 'Intune/Push Wake: ' + $titleReason + ' → ' + $severityLabel

    $stateDescriptor = if ($severity -eq 'high') { 'blocked' } else { 'misconfigured' }
    $explanation = 'Push wake is {0}: StartType={1}; Task.Enabled={2}; LastResult={3}; LastRun={4}; RecentErrors={5}.' -f $stateDescriptor, $serviceStartTypeText, $taskEnabledText, $lastResultRaw, $lastRunText, $recentErrorsText

    $remediation = 'Set dmwappushservice to Automatic (Delayed Start), enable the PushLaunch scheduled task, and re-run the task so Intune push wake requests reach the device.'
    $remediationScript = @(
        'sc config dmwappushservice start= delayed-auto',
        'sc start dmwappushservice',
        'schtasks /Change /TN "\\Microsoft\\Windows\\PushToInstall\\PushLaunch" /Enable',
        'schtasks /Run /TN "\\Microsoft\\Windows\\PushToInstall\\PushLaunch"'
    ) -join "`n"

    $issueParams = @{
        CategoryResult = $Result
        Severity       = $severity
        Title          = $title
        Evidence       = $evidenceLines
        Subcategory    = 'Enrollment & Connectivity'
        Explanation    = $explanation
    }

    if ($severity -in @('high','medium')) {
        $issueParams['Remediation'] = $remediation
        $issueParams['RemediationScript'] = $remediationScript
    }

    Add-CategoryIssue @issueParams

    if ($dataGaps.Count -gt 0) {
        foreach ($gap in $dataGaps) {
            $gapExplanation = 'Push wake is unverified: StartType={0}; Task.Enabled={1}; LastResult={2}; LastRun={3}; RecentErrors={4}.' -f $serviceStartTypeText, $taskEnabledText, $lastResultRaw, $lastRunText, $recentErrorsText
            Add-CategoryIssue -CategoryResult $Result -Severity 'info' -Title $gap -Subcategory 'Enrollment & Connectivity' -Explanation $gapExplanation
        }
    }
}
