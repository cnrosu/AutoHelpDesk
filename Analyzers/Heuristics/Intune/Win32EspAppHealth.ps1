<#!
.SYNOPSIS
    Reviews Intune Management Extension Win32 ESP logs for failing or stalled application installations.
#>

function Invoke-IntuneHeuristic-Win32EspAppHealth {
    param(
        [Parameter(Mandatory)]
        $Context,

        [Parameter(Mandatory)]
        $Result
    )

    Write-HeuristicDebug -Source 'Intune/Win32EspAppHealth' -Message 'Evaluating Win32 ESP app signals'

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

    Write-HeuristicDebug -Source 'Intune/Win32EspAppHealth' -Message 'Win32 ESP evaluation summary' -Data ([ordered]@{
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

    Add-CategoryIssue -CategoryResult $Result -Severity $severity -Title $impactText -Evidence $evidence -Subcategory 'ESP & App Provisioning' -Remediation $remediation -RemediationScript $remediationScript
}
