<#!
.SYNOPSIS
    Intune enrollment and connectivity heuristics.
#>

. (Join-Path -Path (Split-Path $PSScriptRoot -Parent) -ChildPath 'AnalyzerCommon.ps1')
$intuneParserPath = Join-Path -Path (Split-Path $PSScriptRoot -Parent) -ChildPath 'Parsers/IntuneParsers.ps1'
if (Test-Path -LiteralPath $intuneParserPath) {
    . $intuneParserPath
}

function Invoke-IntuneHeuristics {
    param(
        [Parameter(Mandatory)]
        $Context
    )

    Write-HeuristicDebug -Source 'Intune' -Message 'Starting Intune heuristics evaluation' -Data ([ordered]@{
        HasArtifacts = [bool]($Context -and $Context.Artifacts)
    })

    $result = New-CategoryResult -Name 'Intune'
    Invoke-IntuneHeuristic-INTUNE-001 -Context $Context -Result $result
    Invoke-IntuneHeuristic-INTUNE-002 -Context $Context -Result $result
    Invoke-IntuneHeuristic-INTUNE-003 -Context $Context -Result $result
    return $result
}

function Invoke-IntuneHeuristic-INTUNE-001 {
    param(
        [Parameter(Mandatory)]
        $Context,

        [Parameter(Mandatory)]
        $Result
    )

    Write-HeuristicDebug -Source 'Intune/INTUNE-001' -Message 'Evaluating INTUNE-001 signals'

    $dsregText = Get-IntuneDsregText -Context $Context
    $dsregStatus = Parse-IntuneDsregStatus -Text $dsregText

    $w32tmStatus = Get-IntuneW32tmStatus -Context $Context
    $timeMetrics = Parse-IntuneTimeSkew -Status $w32tmStatus

    $caSummary = Get-IntuneConditionalAccessSummary -Context $Context
    $tokenSummary = Get-IntuneTokenFailureSummary -Context $Context

    $isAzureJoined = $false
    $hasAzureSignal = $false
    if ($dsregStatus.AzureAdJoined) {
        $hasAzureSignal = $true
        $value = $dsregStatus.AzureAdJoined.Trim().ToUpperInvariant()
        $isAzureJoined = ($value -eq 'YES' -or $value -eq 'TRUE')
    }

    $hasPrt = $null
    if ($dsregStatus.PrimaryRefreshToken) {
        $value = $dsregStatus.PrimaryRefreshToken.Trim().ToUpperInvariant()
        if ($value -eq 'YES' -or $value -eq 'TRUE') {
            $hasPrt = $true
        } elseif ($value -eq 'NO' -or $value -eq 'FALSE') {
            $hasPrt = $false
        }
    }

    $timeSkewSeconds = $timeMetrics.OffsetSeconds
    $timeSkewMagnitude = if ($timeSkewSeconds -ne $null) { [math]::Abs([int]$timeSkewSeconds) } else { $null }

    $caBlocked = $false
    if ($caSummary) {
        $status = if ($caSummary.Status) { $caSummary.Status.Trim().ToLowerInvariant() } else { $null }
        if ($status -eq 'blocked' -or $status -eq 'deny' -or $status -eq 'denied') {
            $caBlocked = $true
        }
    }

    $recentTokenFailures = if ($tokenSummary) { [int]$tokenSummary.RecentCount } else { 0 }
    $tokenFailureMessage = if ($tokenSummary) { $tokenSummary.LastError } else { $null }
    $tokenFailureTime = if ($tokenSummary) { $tokenSummary.LastTimeUtc } else { $null }

    $needsFinding = $false
    $severity = 'medium'
    $reasons = New-Object System.Collections.Generic.List[string]
    $dataGaps = New-Object System.Collections.Generic.List[string]

    if ($hasAzureSignal) {
        if (-not $isAzureJoined) {
            $reasons.Add('the device is not Azure AD joined') | Out-Null
            $needsFinding = $true
            $severity = 'medium'
        }
    } else {
        $dataGaps.Add('Azure AD join status was not collected') | Out-Null
    }

    if ($hasPrt -eq $false) {
        $reasons.Add('the Primary Refresh Token is unavailable') | Out-Null
        $needsFinding = $true
        if ($severity -eq 'medium' -and $isAzureJoined) {
            $severity = 'low'
        }
    }

    if ($timeSkewMagnitude -ne $null -and $timeSkewMagnitude -gt 300) {
        $directionText = if ($timeSkewSeconds -lt 0) {
            'the device clock is behind by {0}s' -f $timeSkewMagnitude
        } else {
            'the device clock is ahead by {0}s' -f $timeSkewMagnitude
        }
        $reasons.Add($directionText) | Out-Null
        $needsFinding = $true
        $severity = 'medium'
    }

    if ($caBlocked) {
        $needsFinding = $true
        if ($recentTokenFailures -ge 3 -and $tokenFailureTime) {
            $severity = 'critical'
            $reasons.Add('conditional access blocked Join/Register after repeated token failures') | Out-Null
        } else {
            $severity = 'high'
            $reasons.Add('conditional access blocked the Intune join or registration flow') | Out-Null
        }
    }

    if (-not $needsFinding) {
        if ($isAzureJoined -and $hasPrt -eq $true) {
            Add-CategoryNormal -CategoryResult $Result -Title 'Device is Azure AD joined with a valid Primary Refresh Token and healthy time sync for Intune enrollment.' -Subcategory 'Enrollment & Connectivity'
        } elseif ($isAzureJoined -and $hasPrt -eq $null) {
            Add-CategoryNormal -CategoryResult $Result -Title 'Device is Azure AD joined and time sync appears healthy; PRT status was not reported.' -Subcategory 'Enrollment & Connectivity'
        }

        if ($dataGaps.Count -gt 0) {
            $gapTitle = 'Intune diagnostics were incomplete, so Azure AD join signals were unavailable.'
            Add-CategoryIssue -CategoryResult $Result -CardId 'Intune.ps1/gaptitle' -Data ([ordered]@{ gapTitle = $gapTitle })
        }
        return
    }

    if ($severity -eq 'medium' -and $hasPrt -eq $false -and $isAzureJoined -and (($timeSkewMagnitude -eq $null) -or $timeSkewMagnitude -le 300)) {
        $severity = 'low'
    }

    $reasonText = if ($reasons.Count -gt 0) { $reasons -join ' and ' } else { 'Intune prerequisites are missing' }
    $title = 'Device cannot connect to Intune because ' + $reasonText + ', so enrollment and policy sync requests fail.'

    $lastErrorParts = New-Object System.Collections.Generic.List[string]
    if ($dsregStatus.LastErrorCode) { $lastErrorParts.Add([string]$dsregStatus.LastErrorCode) | Out-Null }
    if ($dsregStatus.LastErrorText) { $lastErrorParts.Add([string]$dsregStatus.LastErrorText) | Out-Null }
    if ($lastErrorParts.Count -eq 0 -and $tokenFailureMessage) {
        $lastErrorParts.Add($tokenFailureMessage) | Out-Null
    }

    $caStatusValue = 'Not collected'
    $caPolicyValue = 'N/A'
    if ($caSummary) {
        if ($caSummary.Status) { $caStatusValue = [string]$caSummary.Status } else { $caStatusValue = 'Unknown' }
        if ($caSummary.PolicyName) { $caPolicyValue = [string]$caSummary.PolicyName }
        if (-not $caSummary.PolicyName -and $caSummary.Scenario) { $caPolicyValue = [string]$caSummary.Scenario }
    }

    $evidence = [ordered]@{
        AzureAdJoined   = if ($dsregStatus.AzureAdJoined) { $dsregStatus.AzureAdJoined } else { 'Unknown' }
        PRT             = if ($dsregStatus.PrimaryRefreshToken) { $dsregStatus.PrimaryRefreshToken } elseif ($hasPrt -eq $false) { 'NO' } elseif ($hasPrt) { 'YES' } else { 'Unknown' }
        TimeSkewSeconds = if ($timeSkewSeconds -ne $null) { $timeSkewSeconds } else { 'Unknown' }
        LastAADError    = if ($lastErrorParts.Count -gt 0) { $lastErrorParts -join ' ' } else { 'Unavailable' }
        CAResult        = ('{0}:{1}' -f $caStatusValue, $caPolicyValue)
        TokenFailures2h = $recentTokenFailures
    }

    $remediation = 'Resync device time, rebind the work account, and allow initial Intune registration in conditional access.'
    $remediationScript = @(
        'w32tm /resync',
        'dsregcmd /status',
        'Settings > Accounts > Access work or school > Disconnect > Re-add'
    ) -join "`n"

    $issueData = [ordered]@{
        title                 = $title
        severity              = $severity
        reasons               = @($reasons.ToArray())
        dataGaps              = @($dataGaps.ToArray())
        tokenFailures         = if ($tokenSummary) {
            @([ordered]@{
                Count       = $recentTokenFailures
                LastError   = $tokenFailureMessage
                LastTimeUtc = $tokenFailureTime
            })
        } else { @() }
        diagnostics          = [ordered]@{
            AzureAdJoined        = $evidence.AzureAdJoined
            PrimaryRefreshToken  = $evidence.PRT
            TimeSkewSeconds      = $timeSkewSeconds
            ConditionalAccess    = $evidence.CAResult
            TokenFailures2h      = $recentTokenFailures
        }
        remediationSummary   = $remediation
        remediationSteps     = @(
            'Resync device time to eliminate clock skew before Azure AD token requests.'
            'Disconnect and re-add the work account to refresh the Primary Refresh Token.'
            'Review conditional access so first-time Intune registration is allowed.'
        )
        remediationScriptLines = $remediationScript -split "`n"
    }

    Add-CategoryIssue -CategoryResult $Result -CardId 'Intune.ps1/title' -Severity $severity -Evidence $evidence -Remediation $remediation -RemediationScript $remediationScript -Data $issueData

    if ($dataGaps.Count -gt 0) {
        $gapTitle = 'Intune diagnostics were incomplete, so Azure AD join signals were unavailable.'
        Add-CategoryIssue -CategoryResult $Result -CardId 'Intune.ps1/gaptitle' -Data ([ordered]@{ gapTitle = $gapTitle })
    }
}

function Invoke-IntuneHeuristic-INTUNE-003 {
    param(
        [Parameter(Mandatory)]
        $Context,

        [Parameter(Mandatory)]
        $Result
    )

    Write-HeuristicDebug -Source 'Intune/INTUNE-003' -Message 'Evaluating INTUNE-003 signals'

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
    Write-HeuristicDebug -Source 'Intune/INTUNE-003' -Message 'Push notification dependency summary' -Data $debugData

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
                Add-CategoryIssue -CategoryResult $Result -CardId 'Intune.ps1/gaptitle' -Data ([ordered]@{ gapTitle = $gap })
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

    $issueData = [ordered]@{
        title                 = $title
        severity              = $severity
        reasons               = @($reasons.ToArray())
        dataGaps              = @($dataGaps.ToArray())
        serviceDiagnostics    = if ($serviceStatus) {
            [ordered]@{
                Found      = $serviceStatus.Found
                StartMode  = $serviceStatus.StartMode
                Status     = $serviceStatus.Status
                Errors     = if ($serviceStatus.Errors) { @($serviceStatus.Errors | Where-Object { $_ }) } else { @() }
            }
        } else { $null }
        taskDiagnostics       = if ($taskStatus) {
            [ordered]@{
                Found        = $taskStatus.Found
                Enabled      = $taskStatus.Enabled
                Status       = $taskStatus.Status
                LastResult   = $taskStatus.LastResult
                Errors       = if ($taskStatus.Errors) { @($taskStatus.Errors | Where-Object { $_ }) } else { @() }
            }
        } else { $null }
        remediationSummary   = $remediation
        remediationSteps     = @(
            'Ensure dmwappushservice is configured for delayed automatic start and is running.'
            'Enable and repair the PushLaunch scheduled task so Intune wake-ups succeed.'
        )
        remediationScriptLines = $remediationScript -split "`n"
    }

    Add-CategoryIssue -CategoryResult $Result -CardId 'Intune.ps1/title' -Severity $severity -Evidence $evidence -Remediation $remediation -RemediationScript $remediationScript -Data $issueData

    if ($dataGaps.Count -gt 0) {
        foreach ($gap in $dataGaps) {
            Add-CategoryIssue -CategoryResult $Result -CardId 'Intune.ps1/gaptitle' -Data ([ordered]@{ gapTitle = $gap })
        }
    }
}

function Invoke-IntuneHeuristic-INTUNE-002 {
    param(
        [Parameter(Mandatory)]
        $Context,

        [Parameter(Mandatory)]
        $Result
    )

    Write-HeuristicDebug -Source 'Intune/INTUNE-002' -Message 'Evaluating INTUNE-002 signals'

    $win32Status = Parse-IntuneImeWin32Status -Context $Context
    if (-not $win32Status) { return }

    if (-not $win32Status.HasLogs) {
        return
    }

    $unattributedLines = if ($win32Status.UnattributedContentLines) { $win32Status.UnattributedContentLines } else { @() }
    $unattributedCount = if ($unattributedLines) { $unattributedLines.Count } else { 0 }

    $problemApps = [System.Collections.Generic.List[pscustomobject]]::new()

    foreach ($app in $win32Status.Apps) {
        if (-not $app) { continue }

        $hasContentErrors = ($app.ContentErrors -and $app.ContentErrors.Count -gt 0)
        $pendingMinutes = $app.PendingMinutes
        $hasMismatch = $app.HasMismatch
        $hasDetectionFalse = ($app.DetectionFalseCount -gt 0)
        $hasExitZero = ($app.ExitZeroCount -gt 0)
        $timeouts = if ($app.TimeoutMentions) { [int]$app.TimeoutMentions } else { 0 }

        $needsAttention = $false
        if ($hasContentErrors -or $hasMismatch) { $needsAttention = $true }
        if (-not $needsAttention -and $hasDetectionFalse -and -not $hasExitZero) {
            if ($pendingMinutes -ne $null -and $pendingMinutes -ge 30) {
                $needsAttention = $true
            }
        }

        if (-not $needsAttention -and $pendingMinutes -ne $null -and $pendingMinutes -ge 45) {
            $needsAttention = $true
        }

        if (-not $needsAttention -and $hasDetectionFalse) {
            $needsAttention = $true
        }

        if (-not $needsAttention -and $timeouts -gt 0) {
            $needsAttention = $true
        }

        if (-not $needsAttention) { continue }

        $lastExit = $null
        if ($app.ExitCodes -and $app.ExitCodes.Count -gt 0) {
            $lastExit = $app.ExitCodes[$app.ExitCodes.Count - 1].Code
        }

        $problemApps.Add([pscustomobject]@{
            Name               = if ($app.Name) { $app.Name } else { 'Unknown app' }
            Id                 = $app.Id
            PendingMinutes     = $pendingMinutes
            DetectionFalse     = $app.DetectionFalseCount
            ExitZero           = $app.ExitZeroCount
            HasMismatch        = $hasMismatch
            HasContentErrors   = $hasContentErrors
            TimeoutMentions    = $timeouts
            LastExitCode       = $lastExit
            ContentErrorCount  = if ($app.ContentErrors) { $app.ContentErrors.Count } else { 0 }
        }) | Out-Null
    }

    if ($problemApps.Count -eq 0 -and $unattributedCount -eq 0) {
        return
    }

    $severity = 'medium'

    $contentApps = @($problemApps | Where-Object { $_.HasContentErrors })
    $mismatchApps = @($problemApps | Where-Object { $_.HasMismatch })
    $longPending = @($problemApps | Where-Object { $_.PendingMinutes -ne $null -and $_.PendingMinutes -ge 45 })
    $shortPending = ($problemApps.Count -eq 1 -and $problemApps[0].PendingMinutes -ne $null -and $problemApps[0].PendingMinutes -lt 30 -and -not $problemApps[0].HasMismatch -and -not $problemApps[0].HasContentErrors -and $problemApps[0].TimeoutMentions -eq 0)
    $timeoutHeavy = @($problemApps | Where-Object { $_.TimeoutMentions -ge 2 })

    if ($contentApps.Count -ge 2) {
        $severity = 'critical'
    } elseif ($contentApps.Count -gt 0 -or $timeoutHeavy.Count -gt 0) {
        $severity = 'high'
    } elseif ($mismatchApps.Count -gt 0 -or $longPending.Count -gt 0) {
        $severity = 'medium'
    } elseif ($shortPending) {
        $severity = 'low'
    }

    if ($problemApps.Count -eq 0 -and $unattributedCount -gt 0) {
        $severity = 'high'
    }

    Write-HeuristicDebug -Source 'Intune/INTUNE-002' -Message 'Win32 ESP evaluation summary' -Data ([ordered]@{
        AppsAnalyzed     = if ($win32Status.Apps) { $win32Status.Apps.Count } else { 0 }
        ProblemApps      = $problemApps.Count
        ContentFailures  = $contentApps.Count
        DetectionMismatches = $mismatchApps.Count
        LongPendingApps  = $longPending.Count
        Unattributed     = $unattributedCount
        Severity         = $severity
    })

    $impactText = if ($problemApps.Count -eq 1) {
        $app = $problemApps[0]
        if ($app.HasContentErrors) {
            "Enrollment is stuck at the ESP because Win32 app '$($app.Name)' cannot download its content, so required software never installs."
        } elseif ($app.HasMismatch) {
            "Enrollment is stuck at the ESP because Win32 app '$($app.Name)' installs but its detection keeps returning False, so setup never completes."
        } elseif ($app.TimeoutMentions -gt 0) {
            "Enrollment is stuck at the ESP because Win32 app '$($app.Name)' keeps timing out during provisioning, so setup never finishes."
        } else {
            "Enrollment is stuck at the ESP because Win32 app '$($app.Name)' has been pending for required detection, so setup remains blocked."
        }
    } elseif ($problemApps.Count -gt 1) {
        "Enrollment is stuck at the ESP because multiple Win32 required apps failed detection or content downloads, so device setup cannot finish."
    } else {
        "Enrollment is stuck at the ESP because Win32 app content could not be downloaded, so required installs never complete."
    }

    $evidenceLines = [System.Collections.Generic.List[string]]::new()
    foreach ($app in $problemApps) {
        $parts = [System.Collections.Generic.List[string]]::new()
        $parts.Add("Name=$($app.Name)") | Out-Null
        if ($app.Id) { $parts.Add("Id=$($app.Id)") | Out-Null }
        if ($app.LastExitCode -ne $null) { $parts.Add("LastExitCode=$($app.LastExitCode)") | Out-Null }
        if ($app.DetectionFalse -gt 0) { $parts.Add("DetectionFalse=$($app.DetectionFalse)") | Out-Null }
        if ($app.ExitZero -gt 0) { $parts.Add("ExitZero=$($app.ExitZero)") | Out-Null }
        if ($app.PendingMinutes -ne $null) { $parts.Add("PendingMinutes=$([math]::Round($app.PendingMinutes, 2))") | Out-Null }
        if ($app.HasContentErrors) { $parts.Add("ContentErrors=$($app.ContentErrorCount)") | Out-Null }
        if ($app.TimeoutMentions -gt 0) { $parts.Add("TimeoutMentions=$($app.TimeoutMentions)") | Out-Null }
        $evidenceLines.Add(($parts -join '; ')) | Out-Null
    }

    if ($unattributedCount -gt 0) {
        $evidenceLines.Add('UnattributedContentErrors=' + (($unattributedLines | Select-Object -First 3) -join ' | ')) | Out-Null
    }

    $evidence = [ordered]@{
        Apps = $evidenceLines -join "`n"
    }

    $remediation = 'Fix the failing detection rules or unblock content delivery so the ESP can complete required Win32 app installs.'
    $remediationScript = @(
        'Validate detection script/registry/file on a healthy device',
        'Temporarily remove app from ESP required list and redeploy'
    ) -join "`n"

    $issueData = [ordered]@{
        impactText            = $impactText
        severity              = $severity
        problemApps           = @(
            $problemApps | ForEach-Object {
                if ($_ ) {
                    [ordered]@{
                        Name              = $_.Name
                        Id                = $_.Id
                        PendingMinutes    = $_.PendingMinutes
                        DetectionFalse    = $_.DetectionFalse
                        ExitZero          = $_.ExitZero
                        HasMismatch       = $_.HasMismatch
                        HasContentErrors  = $_.HasContentErrors
                        TimeoutMentions   = $_.TimeoutMentions
                        LastExitCode      = $_.LastExitCode
                        ContentErrorCount = $_.ContentErrorCount
                    }
                }
            } | Where-Object { $_ }
        )
        unattributedLines     = @($unattributedLines)
        evidenceLines         = @($evidenceLines.ToArray())
        remediationSummary    = $remediation
        remediationSteps      = @(
            'Validate the detection script or rules against a healthy reference device.'
            'Temporarily remove the app from ESP required installs and redeploy after fixes.'
        )
        remediationScriptLines = $remediationScript -split "`n"
    }

    Add-CategoryIssue -CategoryResult $Result -CardId 'Intune.ps1/impacttext' -Severity $severity -Evidence $evidence -Remediation $remediation -RemediationScript $remediationScript -Data $issueData
}
