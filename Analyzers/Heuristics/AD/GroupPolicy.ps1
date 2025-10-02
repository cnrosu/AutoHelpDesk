function Add-AdGroupPolicyFindings {
    param(
        [Parameter(Mandatory)]
        $Result,
        $GpoInfo,
        [string[]]$SharesFailingHosts,
        [bool]$TimeSkewHigh
    )

    if (-not $GpoInfo) { return }

    $gpResult = $GpoInfo.GpResult
    $gpoEvents = @()
    if ($GpoInfo.Events) {
        foreach ($event in $GpoInfo.Events) {
            if ($event -and -not $event.Error) { $gpoEvents += $event }
        }
    }

    $gpResultSuccess = $false
    if ($gpResult -and $gpResult.Succeeded -eq $true) { $gpResultSuccess = $true }

    if ($gpResultSuccess -and $gpoEvents.Count -eq 0) {
        Add-CategoryNormal -CategoryResult $Result -Title 'GOOD GPO (processed successfully)' -Subcategory 'Group Policy'
        return
    }

    $severity = 'medium'
    if ($gpoEvents.Count -ge 5 -and $SharesFailingHosts.Count -gt 0) { $severity = 'high' }
    $title = "GPO processing errors, so device policies aren't applied"
    if ($TimeSkewHigh) {
        $titleBuilder = [System.Text.StringBuilder]::new()
        $null = $titleBuilder.Append($title)
        $null = $titleBuilder.Append(' related to time skew')
        $title = $titleBuilder.ToString()
    }
    $evidenceBuilder = [System.Text.StringBuilder]::new()
    if ($gpResult -and $gpResult.Output) { Add-StringFragment -Builder $evidenceBuilder -Fragment (($gpResult.Output | Select-Object -First 3) -join ' | ') }
    if ($gpResult -and $gpResult.Error) { Add-StringFragment -Builder $evidenceBuilder -Fragment $gpResult.Error }
    if ($gpoEvents.Count -gt 0) {
        $eventGroups = $gpoEvents | Group-Object -Property Id
        $eventSummaryParts = [System.Collections.Generic.List[string]]::new()
        foreach ($group in $eventGroups) {
            $null = $eventSummaryParts.Add(("{0}x{1}" -f $group.Count, $group.Name))
        }

        $eventSummary = ($eventSummaryParts -join ', ')
        if ($eventSummary) { Add-StringFragment -Builder $evidenceBuilder -Fragment $eventSummary }
    }
    if ($evidenceBuilder.Length -eq 0) { Add-StringFragment -Builder $evidenceBuilder -Fragment 'GPO data unavailable' }
    Add-CategoryIssue -CategoryResult $Result -Severity $severity -Title $title -Evidence $evidenceBuilder.ToString() -Subcategory 'Group Policy'
}

function Add-AdGroupPolicyEventLogFindings {
    param(
        [Parameter(Mandatory)]
        $Result,
        $EventsPayload
    )

    if (-not $EventsPayload -or -not $EventsPayload.GroupPolicy) { return }

    $groupPolicyLog = $EventsPayload.GroupPolicy
    if ($groupPolicyLog.Error) {
        Add-CategoryIssue -CategoryResult $Result -Severity 'info' -Title 'Unable to read Group Policy event log, so device policy failures may be hidden.' -Evidence $groupPolicyLog.Error -Subcategory 'Group Policy'
        return
    }

    $entries = if ($groupPolicyLog -is [System.Collections.IEnumerable] -and -not ($groupPolicyLog -is [string])) { @($groupPolicyLog) } else { @($groupPolicyLog) }
    $sysvolMatches = $entries | Where-Object { $_.Message -match '(?i)\\\\[^\r\n]+\\(SYSVOL|NETLOGON)' -or $_.Message -match '(?i)The network path was not found' -or $_.Message -match '(?i)The system cannot find the path specified' }
    if ($sysvolMatches.Count -gt 0) {
        $selectedSysvolMatches = $sysvolMatches | Select-Object -First 3
        $sysvolEvidence = [System.Collections.Generic.List[string]]::new()
        foreach ($entry in $selectedSysvolMatches) {
            $null = $sysvolEvidence.Add(("[{0}] {1}" -f $entry.Id, $entry.Message))
        }

        $evidence = ($sysvolEvidence -join "`n")
        Add-CategoryIssue -CategoryResult $Result -Severity 'high' -Title "Group Policy errors accessing SYSVOL/NETLOGON, so device policies aren't applied." -Evidence $evidence -Subcategory 'Group Policy'
    }

    $gpoFailures = $entries | Where-Object { $_.Id -in 1058, 1030, 1502, 1503 }
    if ($gpoFailures.Count -gt 0) {
        $selectedGpoFailures = $gpoFailures | Select-Object -First 3
        $gpoFailureEvidence = [System.Collections.Generic.List[string]]::new()
        foreach ($entry in $selectedGpoFailures) {
            $null = $gpoFailureEvidence.Add(("[{0}] {1}" -f $entry.Id, $entry.Message))
        }

        $evidence = ($gpoFailureEvidence -join "`n")
        Add-CategoryIssue -CategoryResult $Result -Severity 'medium' -Title "Group Policy processing failures detected, so device policies aren't applied." -Evidence $evidence -Subcategory 'Group Policy'
    }
}
