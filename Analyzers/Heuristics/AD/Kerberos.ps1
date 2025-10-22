function Add-AdKerberosFindings {
    param(
        [Parameter(Mandatory)]
        $Result,
        $KerberosInfo,
        [bool]$NoDcReachable,
        [bool]$TimeSkewHigh
    )

    if (-not $KerberosInfo) {
        return [pscustomobject]@{ FailureCount = 0 }
    }

    $kerberosEvents = @()
    if ($KerberosInfo.Events) {
        foreach ($event in $KerberosInfo.Events) {
            if ($event -and -not $event.Error) { $kerberosEvents += $event }
        }
    }

    $failureEvents = $kerberosEvents | Where-Object { $_.Id -in 4768, 4771, 4776 }
    $failureCount = $failureEvents.Count

    if ($KerberosInfo.Parsed -and $KerberosInfo.Parsed.HasTgt -ne $true) {
        $title = "Kerberos TGT not present, breaking Active Directory authentication."
        $evidencePartsBuilder = [System.Text.StringBuilder]::new()
        Add-StringFragment -Builder $evidencePartsBuilder -Fragment 'klist output missing krbtgt ticket'
        if ($KerberosInfo.Parsed.PSObject.Properties['TgtRealm'] -and $KerberosInfo.Parsed.TgtRealm) {
            Add-StringFragment -Builder $evidencePartsBuilder -Fragment ("Expected realm: {0}" -f $KerberosInfo.Parsed.TgtRealm)
        }
        if ($NoDcReachable) { Add-StringFragment -Builder $evidencePartsBuilder -Fragment 'likely off network' }
        Add-CategoryIssue -CategoryResult $Result -Severity 'medium' -Title $title -Evidence $evidencePartsBuilder.ToString() -Subcategory 'Kerberos' -Remediation (Get-AdKerberosSecureChannelTimeRemediation)
    }

    if ($failureCount -gt 0) {
        $severity = if ($failureCount -ge 15) { 'high' } else { 'medium' }
        if ($NoDcReachable -and $severity -eq 'high') { $severity = 'medium' }
        $failureGroups = $failureEvents | Group-Object -Property Id
        $failureSummaryParts = [System.Collections.Generic.List[string]]::new()
        foreach ($group in $failureGroups) {
            $null = $failureSummaryParts.Add(("{0}x{1}" -f $group.Count, $group.Name))
        }

        $failureSummary = ($failureSummaryParts -join ', ')
        $evidenceLines = [System.Collections.Generic.List[string]]::new()
        $null = $evidenceLines.Add(("Failure summary: {0}" -f $failureSummary))
        $null = $evidenceLines.Add(("Total failure events: {0}" -f $failureCount))
        $null = $evidenceLines.Add(("No DC reachable: {0}" -f ([bool]$NoDcReachable)))
        $null = $evidenceLines.Add(("Time skew high: {0}" -f ([bool]$TimeSkewHigh)))

        if ($failureEvents -and $failureEvents.Count -gt 0) {
            $sampleCount = [System.Math]::Min(3, $failureEvents.Count)
            $eventSamples = $failureEvents | Select-Object -First $sampleCount
            $eventSamplesJson = $null
            try {
                $eventSamplesJson = $eventSamples | ConvertTo-Json -Depth 6
            } catch {
                $eventSamplesJson = $null
            }

            if ($eventSamplesJson) {
                $null = $evidenceLines.Add(("Event samples:`n{0}" -f $eventSamplesJson))
            } else {
                foreach ($sample in $eventSamples) {
                    $sampleText = ($sample | Out-String).Trim()
                    if (-not [string]::IsNullOrWhiteSpace($sampleText)) {
                        $null = $evidenceLines.Add(("Event sample: {0}" -f $sampleText))
                    }
                }
            }
        }

        $explanation = ('Kerberos authentication attempts failed {0} times ({1}). Domain controller reachable flag: {2}. Time skew high: {3}.' -f $failureCount, $failureSummary, [bool]$NoDcReachable, [bool]$TimeSkewHigh)
        Add-CategoryIssue -CategoryResult $Result -Severity $severity -Title ("Kerberos failures detected: {0}" -f $failureSummary) -Evidence ($evidenceLines.ToArray()) -Explanation $explanation -Subcategory 'Kerberos' -Area 'AD/Kerberos' -Remediation (Get-AdKerberosSecureChannelTimeRemediation)
    }

    [pscustomobject]@{
        FailureCount = $failureCount
    }
}
