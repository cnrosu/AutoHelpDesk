<#!
.SYNOPSIS
    Evaluates Azure AD join, PRT, time sync, and conditional access signals for Intune enrollment health.
#>

function Invoke-IntuneHeuristic-EnrollmentConnectivityHealth {
    param(
        [Parameter(Mandatory)]
        $Context,

        [Parameter(Mandatory)]
        $Result
    )

    Write-HeuristicDebug -Source 'Intune/EnrollmentConnectivityHealth' -Message 'Evaluating enrollment connectivity signals'

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
            Add-CategoryIssue -CategoryResult $Result -Severity 'info' -Title $gapTitle -Subcategory 'Enrollment & Connectivity'
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

    Add-CategoryIssue -CategoryResult $Result -Severity $severity -Title $title -Evidence $evidence -Subcategory 'Enrollment & Connectivity' -Remediation $remediation -RemediationScript $remediationScript

    if ($dataGaps.Count -gt 0) {
        $gapTitle = 'Intune diagnostics were incomplete, so Azure AD join signals were unavailable.'
        Add-CategoryIssue -CategoryResult $Result -Severity 'info' -Title $gapTitle -Subcategory 'Enrollment & Connectivity'
    }
}
