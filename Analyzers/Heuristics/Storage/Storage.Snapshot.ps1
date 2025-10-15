function Invoke-StorageSnapshotEvaluation {
    param(
        [Parameter(Mandatory)]
        $CategoryResult,
        $SnapshotPayload
    )

    if (-not $SnapshotPayload -or -not $SnapshotPayload.PSObject.Properties['DiskDrives']) { return }

    $smartData = $SnapshotPayload.DiskDrives
    if ($smartData -is [pscustomobject] -and $smartData.PSObject.Properties['Error']) {
        $errorDetail = $smartData.Error
        if (-not [string]::IsNullOrWhiteSpace($errorDetail)) {
            Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'warning' -Title 'SMART status unavailable, so imminent drive failure may be missed.' -Evidence $errorDetail -Subcategory 'SMART'
        }
        return
    }

    $smartText = if ($smartData -is [string]) { $smartData } else { [string]$smartData }
    if ([string]::IsNullOrWhiteSpace($smartText)) { return }

    $failurePattern = '(?i)\b(Pred\s*Fail|Fail(?:ed|ing)?|Bad|Caution)\b'
    if ($smartText -match $failurePattern) {
        $failureMatches = [regex]::Matches($smartText, $failurePattern)
        $keywordCandidates = [System.Collections.Generic.List[string]]::new()
        foreach ($match in $failureMatches) {
            $trimmed = $match.Value.Trim()
            if ($trimmed) { $null = $keywordCandidates.Add($trimmed) }
        }

        $keywords = $keywordCandidates | Sort-Object -Unique
        $keywordSummary = if ($keywords) { $keywords -join ', ' } else { $null }
        $evidenceLines = ([regex]::Split($smartText,'\r?\n') | Where-Object { $_ -match $failurePattern } | Select-Object -First 12)
        if (-not $evidenceLines -or $evidenceLines.Count -eq 0) {
            $evidenceLines = ([regex]::Split($smartText,'\r?\n') | Select-Object -First 12)
        }
        $evidenceText = ($evidenceLines -join "`n").TrimEnd()
        $message = if ($keywordSummary) {
            "SMART status reports failure indicators ({0})." -f $keywordSummary
        } else {
            'SMART status reports failure indicators.'
        }
        Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'critical' -Title $message -Evidence $evidenceText -Subcategory 'SMART'
    } elseif ($smartText -notmatch '(?i)Unknown') {
        $preview = Get-StoragePreview -Text $smartText
        if ($preview) {
            Add-CategoryNormal -CategoryResult $CategoryResult -Title 'SMART status shows no failure indicators' -Evidence $preview -Subcategory 'SMART'
        } else {
            Add-CategoryNormal -CategoryResult $CategoryResult -Title 'SMART status shows no failure indicators' -Subcategory 'SMART'
        }
    }
}
