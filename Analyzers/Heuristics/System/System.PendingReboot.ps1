function Update-SystemPendingRebootInsights {
    param(
        [Parameter(Mandatory)]
        $Context,

        [Parameter(Mandatory)]
        $Result
    )

    $pendingRebootArtifact = Get-AnalyzerArtifact -Context $Context -Name 'pending-reboot'
    if ($pendingRebootArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $pendingRebootArtifact)
        if ($payload -and $payload.Registry) {
            $entries = @($payload.Registry)

            $presentEntries = @($entries | Where-Object { $_ -and $_.PSObject.Properties['Present'] -and $_.Present })
            $evidenceLines = New-Object System.Collections.Generic.List[string]

            foreach ($entry in $entries) {
                $descriptor = if ($entry.ValueName) { "{0}::{1}" -f $entry.Path, $entry.ValueName } else { [string]$entry.Path }
                $status = if ($entry.Present) { 'present' } else { 'absent' }
                $timestamp = if ($entry.LastWriteTime) { [string]$entry.LastWriteTime } else { 'timestamp unavailable' }

                $additional = $null
                if ($entry.PSObject.Properties['Values'] -and $entry.Values) {
                    if ($entry.Values -is [System.Collections.IEnumerable] -and -not ($entry.Values -is [string])) {
                        $additional = "values={0}" -f ((@($entry.Values) | Select-Object -First 3) -join ', ')
                    } else {
                        $additional = "value={0}" -f $entry.Values
                    }
                } elseif ($entry.PSObject.Properties['ValueReadError'] -and $entry.ValueReadError) {
                    $additional = "value read error: {0}" -f $entry.ValueReadError
                } elseif ($entry.PSObject.Properties['Error'] -and $entry.Error) {
                    $additional = "error: {0}" -f $entry.Error
                }

                $lineParts = @("{0} → {1}" -f $descriptor, $status)
                $lineParts += "LastWriteTime={0}" -f $timestamp
                if ($additional) { $lineParts += $additional }
                $evidenceLines.Add(($lineParts -join ' | ')) | Out-Null
            }

            $oldestRecord = $null
            foreach ($entry in $presentEntries) {
                if (-not ($entry.PSObject.Properties['LastWriteTime']) -or -not $entry.LastWriteTime) { continue }
                try {
                    $parsed = [datetime]::Parse($entry.LastWriteTime)
                } catch {
                    continue
                }

                if (-not $oldestRecord -or $parsed -lt $oldestRecord.Timestamp) {
                    $oldestRecord = [pscustomobject]@{ Entry = $entry; Timestamp = $parsed }
                }
            }

            if ($presentEntries.Count -gt 0) {
                $now = Get-Date
                $severity = 'medium'
                $title = 'Pending reboot required'
                if ($oldestRecord) {
                    $age = $now - $oldestRecord.Timestamp
                    if ($age.TotalDays -ge 7) {
                        $severity = 'high'
                        $title = 'Pending reboot overdue'
                    }

                    $descriptor = if ($oldestRecord.Entry.ValueName) { "{0}::{1}" -f $oldestRecord.Entry.Path, $oldestRecord.Entry.ValueName } else { [string]$oldestRecord.Entry.Path }
                    $ageLine = "Oldest pending marker: {0} (recorded {1:yyyy-MM-ddTHH:mm:ssK}, ~{2:N1} days ago)" -f $descriptor, $oldestRecord.Timestamp, $age.TotalDays
                    $evidenceLines.Add($ageLine) | Out-Null
                }

                $evidence = $evidenceLines -join "`n"
                Add-CategoryIssue -CategoryResult $Result -Severity $severity -Title $title -Evidence $evidence -Subcategory 'Pending Reboot' -CheckId 'System/PendingReboot'
            } else {
                $evidence = $evidenceLines -join "`n"
                if (-not [string]::IsNullOrWhiteSpace($evidence)) {
                    Add-CategoryNormal -CategoryResult $Result -Title 'No reboot pending' -Evidence $evidence -CheckId 'System/PendingReboot'
                } else {
                    Add-CategoryNormal -CategoryResult $Result -Title 'No reboot pending' -CheckId 'System/PendingReboot'
                }
            }
        } else {
            Add-CategoryIssue -CategoryResult $Result -Severity 'info' -Title 'Pending reboot data unavailable' -Subcategory 'Pending Reboot' -CheckId 'System/PendingReboot'
        }
    } else {
        Add-CategoryIssue -CategoryResult $Result -Severity 'info' -Title 'Pending reboot artifact missing' -Subcategory 'Pending Reboot' -CheckId 'System/PendingReboot'
    }
}
