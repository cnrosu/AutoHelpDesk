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

    Write-HeuristicDebug -Source 'Intune/PushNotificationQuickSync' -Message 'Evaluating Windows Push Notification Service status'

    $serviceStatus = Get-IntunePushNotificationServiceStatus -Context $Context

    $serviceFound = ($serviceStatus -and $serviceStatus.Found)
    $startModeNormalized = if ($serviceStatus) { $serviceStatus.StartModeNormalized } else { $null }
    if (-not $startModeNormalized) { $startModeNormalized = 'unknown' }

    $serviceStartTypeText = if ($serviceStatus -and $serviceStatus.StartMode) { [string]$serviceStatus.StartMode } else { $null }
    if (-not $serviceStartTypeText) {
        switch ($startModeNormalized) {
            'automatic'         { $serviceStartTypeText = 'Automatic'; break }
            'automatic-delayed' { $serviceStartTypeText = 'AutomaticDelayedStart'; break }
            'manual'            { $serviceStartTypeText = 'Manual'; break }
            'disabled'          { $serviceStartTypeText = 'Disabled'; break }
            default             { $serviceStartTypeText = 'Unknown'; break }
        }
    }

    $statusText = 'Unknown'
    if ($serviceStatus) {
        if ($serviceStatus.State) { $statusText = [string]$serviceStatus.State }
        elseif ($serviceStatus.Status) { $statusText = [string]$serviceStatus.Status }
    }
    if (-not $statusText) { $statusText = 'Unknown' }

    $lastStartError = 'N/A'
    if ($serviceStatus -and $serviceStatus.Errors -and $serviceStatus.Errors.Count -gt 0) {
        $errorText = ($serviceStatus.Errors | Where-Object { $_ } | Select-Object -First 1)
        if ($errorText) { $lastStartError = [string]$errorText }
    }

    $evidenceLines = [System.Collections.Generic.List[string]]::new()
    $serviceEvidence = 'Service: dmwappushservice → Found={0}; StartType={1}; Status={2}; LastStartError={3}' -f ([string]$serviceFound), $serviceStartTypeText, $statusText, $lastStartError
    $evidenceLines.Add($serviceEvidence) | Out-Null

    $serviceDisabled = ($startModeNormalized -eq 'disabled')
    $serviceAuto = ($startModeNormalized -in @('automatic','automatic-delayed'))
    $serviceFailure = ($serviceFound -and -not $serviceDisabled -and $serviceStatus -and $serviceStatus.Errors -and $serviceStatus.Errors.Count -gt 0)

    $remediation = 'Set dmwappushservice to Automatic (Delayed Start) and start it so Intune push wake requests reach the device.'
    $remediationScript = @(
        'sc config dmwappushservice start= delayed-auto',
        'sc start dmwappushservice'
    ) -join "`n"

    if (-not $serviceFound) {
        $title = 'Intune/Push Wake: Windows Push Notification Service missing → High'
        $explanation = 'Intune push notifications cannot reach the device because the Windows Push Notification Service is missing, so push wake requests from Intune will not arrive.'
        Add-CategoryIssue -CategoryResult $Result -Severity 'high' -Title $title -Evidence $evidenceLines -Subcategory 'Enrollment & Connectivity' -Explanation $explanation -Remediation $remediation -RemediationScript $remediationScript
        return
    }

    if ($serviceDisabled) {
        $title = 'Intune/Push Wake: Windows Push Notification Service disabled → High'
        $explanation = 'Intune push notifications cannot reach the device because the Windows Push Notification Service is disabled, so push wake requests from Intune will not arrive.'
        Add-CategoryIssue -CategoryResult $Result -Severity 'high' -Title $title -Evidence $evidenceLines -Subcategory 'Enrollment & Connectivity' -Explanation $explanation -Remediation $remediation -RemediationScript $remediationScript
        return
    }

    if ($serviceFailure) {
        $title = 'Intune/Push Wake: Windows Push Notification Service failed to start → High'
        $explanation = 'Intune push notifications cannot reach the device because the Windows Push Notification Service failed to start (LastStartError=' + $lastStartError + '), so push wake requests from Intune will not arrive.'
        Add-CategoryIssue -CategoryResult $Result -Severity 'high' -Title $title -Evidence $evidenceLines -Subcategory 'Enrollment & Connectivity' -Explanation $explanation -Remediation $remediation -RemediationScript $remediationScript
        return
    }

    if ($serviceAuto) {
        $title = 'Intune push wake prerequisites are ready: StartType={0}; Status={1}; LastStartError={2}.' -f $serviceStartTypeText, $statusText, $lastStartError
        Add-CategoryNormal -CategoryResult $Result -Title $title -Evidence $evidenceLines -Subcategory 'Enrollment & Connectivity'
    }
}
