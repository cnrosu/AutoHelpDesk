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

    $serviceCollected = ($serviceStatus -and $serviceStatus.Collected)
    $taskCollected = ($taskStatus -and $taskStatus.Collected)

    $debugData = [ordered]@{
        ServiceCollected = $serviceCollected
        ServiceFound     = if ($serviceStatus) { $serviceStatus.Found } else { $null }
        ServiceStart     = if ($serviceStatus) { $serviceStatus.StartModeNormalized } else { $null }
        ServiceStatus    = if ($serviceStatus) { $serviceStatus.StatusNormalized } else { $null }
        TaskCollected    = $taskCollected
        TaskFound        = if ($taskStatus) { $taskStatus.Found } else { $null }
        TaskEnabled      = if ($taskStatus) { $taskStatus.Enabled } else { $null }
        TaskStatus       = if ($taskStatus) { $taskStatus.StatusNormalized } else { $null }
        TaskResult       = if ($taskStatus) { $taskStatus.LastResultNormalized } else { $null }
    }
    Write-HeuristicDebug -Source 'Intune/PushNotificationQuickSync' -Message 'Push notification dependency summary' -Data $debugData

    $serviceHealthy = $false
    if ($serviceCollected -and $serviceStatus.Found) {
        $serviceHealthy = ($serviceStatus.StartModeNormalized -match '^automatic' -and $serviceStatus.StatusNormalized -eq 'running')
    }

    $taskHealthy = $false
    if ($taskCollected -and $taskStatus.Found) {
        $statusOk = ($taskStatus.StatusNormalized -in @('ready','running','queued','other'))
        $resultOk = ($taskStatus.LastResultNormalized -in @('success','unknown'))
        $enabledOk = ($null -eq $taskStatus.Enabled -or $taskStatus.Enabled -eq $true)
        $taskHealthy = ($statusOk -and $resultOk -and $enabledOk)
    }

    if ($serviceHealthy -and $taskHealthy) {
        Add-CategoryNormal -CategoryResult $Result -Title 'Windows push notifications and PushLaunch task are healthy, so Intune quick sync wake-ups can reach the device.' -Subcategory 'Enrollment & Connectivity'
        return
    }

    $reasons = New-Object System.Collections.Generic.List[string]
    $dataGaps = New-Object System.Collections.Generic.List[string]

    if (-not $serviceCollected) {
        $gapBase = 'Intune diagnostics were incomplete, so Windows push notification service status was unavailable'
        if ($serviceStatus -and $serviceStatus.Errors -and $serviceStatus.Errors.Count -gt 0) {
            $gapText = '{0} ({1}).' -f $gapBase, (($serviceStatus.Errors | Where-Object { $_ }) -join '; ')
        } else {
            $gapText = $gapBase + '.'
        }
        $dataGaps.Add($gapText) | Out-Null
    }

    if (-not $taskCollected) {
        $gapBase = 'Intune diagnostics were incomplete, so the PushLaunch scheduled task state was unavailable'
        if ($taskStatus -and $taskStatus.Errors -and $taskStatus.Errors.Count -gt 0) {
            $gapText = '{0} ({1}).' -f $gapBase, (($taskStatus.Errors | Where-Object { $_ }) -join '; ')
        } else {
            $gapText = $gapBase + '.'
        }
        $dataGaps.Add($gapText) | Out-Null
    }

    $serviceProblem = $false
    if ($serviceCollected) {
        if (-not $serviceStatus.Found) {
            $reasons.Add('the Windows Push Notification Service (dmwappushservice) is missing or could not be queried') | Out-Null
            $serviceProblem = $true
        } else {
            $mode = if ($serviceStatus.StartModeNormalized) { $serviceStatus.StartModeNormalized } else { 'unknown' }
            $status = if ($serviceStatus.StatusNormalized) { $serviceStatus.StatusNormalized } else { 'unknown' }

            if ($mode -eq 'disabled') {
                $reasons.Add('the Windows Push Notification Service (dmwappushservice) is disabled') | Out-Null
                $serviceProblem = $true
            } elseif ($mode -eq 'manual') {
                $reasons.Add('the Windows Push Notification Service (dmwappushservice) is set to Manual instead of Automatic') | Out-Null
                $serviceProblem = $true
            } elseif ($mode -like 'automatic*' -and $status -ne 'running') {
                $reasons.Add('the Windows Push Notification Service (dmwappushservice) is stopped even though it should start automatically') | Out-Null
                $serviceProblem = $true
            } elseif ($status -eq 'stopped') {
                $reasons.Add('the Windows Push Notification Service (dmwappushservice) is stopped') | Out-Null
                $serviceProblem = $true
            }
        }
    }

    $taskProblem = $false
    if ($taskCollected) {
        if (-not $taskStatus.Found) {
            $reasons.Add('the PushLaunch scheduled task is missing') | Out-Null
            $taskProblem = $true
        } else {
            if ($taskStatus.Enabled -eq $false) {
                $reasons.Add('the PushLaunch scheduled task is disabled') | Out-Null
                $taskProblem = $true
            }

            if ($taskStatus.StatusNormalized -eq 'error') {
                $statusText = if ($taskStatus.Status) { $taskStatus.Status } else { 'an error state' }
                $reasons.Add("the PushLaunch scheduled task reports status '$statusText'") | Out-Null
                $taskProblem = $true
            } elseif ($taskStatus.StatusNormalized -eq 'disabled') {
                if (-not ($reasons | Where-Object { $_ -match 'disabled' })) {
                    $reasons.Add('the PushLaunch scheduled task reports a disabled state') | Out-Null
                }
                $taskProblem = $true
            }

            if ($taskStatus.LastResultNormalized -eq 'failure') {
                $resultText = if ($taskStatus.LastResult) { $taskStatus.LastResult } else { 'a failure code' }
                $reasons.Add("the PushLaunch scheduled task last run failed with result $resultText") | Out-Null
                $taskProblem = $true
            }
        }
    }

    if (-not $serviceProblem -and -not $taskProblem) {
        if ($dataGaps.Count -gt 0) {
            foreach ($gap in $dataGaps) {
                Add-CategoryIssue -CategoryResult $Result -Severity 'info' -Title $gap -Subcategory 'Enrollment & Connectivity'
            }
        }
        return
    }

    $severity = 'medium'
    if ($serviceProblem -and $taskProblem) {
        $severity = 'critical'
    } elseif ($serviceProblem) {
        if (-not $serviceStatus.Found -or $serviceStatus.StartModeNormalized -eq 'disabled') { $severity = 'high' }
    } elseif ($taskProblem) {
        if (-not $taskStatus.Found -or $taskStatus.Enabled -eq $false -or $taskStatus.StatusNormalized -eq 'error') { $severity = 'high' }
    }

    $reasonText = if ($reasons.Count -gt 0) { $reasons -join ' and ' } else { 'push notification dependencies are misconfigured' }
    $title = 'Intune quick sync never wakes the device because ' + $reasonText + ', so policy and app updates stay pending until someone syncs manually.'

    $evidence = [ordered]@{}
    if ($serviceCollected) {
        $serviceParts = [System.Collections.Generic.List[string]]::new()
        $serviceParts.Add('Found=' + [string]$serviceStatus.Found) | Out-Null
        if ($serviceStatus.StartMode) { $serviceParts.Add('StartMode=' + [string]$serviceStatus.StartMode) | Out-Null }
        if ($serviceStatus.State) { $serviceParts.Add('State=' + [string]$serviceStatus.State) | Out-Null }
        if ($serviceStatus.Status -and $serviceStatus.Status -ne $serviceStatus.State) { $serviceParts.Add('Status=' + [string]$serviceStatus.Status) | Out-Null }
        if ($serviceStatus.Errors -and $serviceStatus.Errors.Count -gt 0) { $serviceParts.Add('Errors=' + (($serviceStatus.Errors | Where-Object { $_ }) -join ' | ')) | Out-Null }
        $evidence['dmwappushservice'] = $serviceParts -join '; '
    }

    if ($taskCollected) {
        $taskParts = [System.Collections.Generic.List[string]]::new()
        $taskParts.Add('Found=' + [string]$taskStatus.Found) | Out-Null
        if ($null -ne $taskStatus.Enabled) { $taskParts.Add('Enabled=' + [string]$taskStatus.Enabled) | Out-Null }
        if ($taskStatus.ScheduledTaskState) { $taskParts.Add('TaskState=' + [string]$taskStatus.ScheduledTaskState) | Out-Null }
        if ($taskStatus.Status) { $taskParts.Add('Status=' + [string]$taskStatus.Status) | Out-Null }
        if ($taskStatus.LastResult) { $taskParts.Add('LastResult=' + [string]$taskStatus.LastResult) | Out-Null }
        if ($taskStatus.LastRunTime) { $taskParts.Add('LastRunTime=' + [string]$taskStatus.LastRunTime) | Out-Null }
        if ($taskStatus.MissedRuns) { $taskParts.Add('MissedRuns=' + [string]$taskStatus.MissedRuns) | Out-Null }
        if ($taskStatus.Errors -and $taskStatus.Errors.Count -gt 0) { $taskParts.Add('Errors=' + (($taskStatus.Errors | Where-Object { $_ }) -join ' | ')) | Out-Null }
        $evidence['PushLaunchTask'] = $taskParts -join '; '
    }

    $remediation = 'Re-enable Windows push notifications and repair the PushLaunch scheduled task so Intune can receive sync wake-ups.'
    $remediationScript = @(
        'sc config dmwappushservice start= delayed-auto',
        'sc start dmwappushservice',
        'schtasks /Change /TN "\\Microsoft\\Windows\\PushToInstall\\PushLaunch" /Enable',
        'schtasks /Run /TN "\\Microsoft\\Windows\\PushToInstall\\PushLaunch"'
    ) -join "`n"

    Add-CategoryIssue -CategoryResult $Result -Severity $severity -Title $title -Evidence $evidence -Subcategory 'Enrollment & Connectivity' -Remediation $remediation -RemediationScript $remediationScript

    if ($dataGaps.Count -gt 0) {
        foreach ($gap in $dataGaps) {
            Add-CategoryIssue -CategoryResult $Result -Severity 'info' -Title $gap -Subcategory 'Enrollment & Connectivity'
        }
    }
}
