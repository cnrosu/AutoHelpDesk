function Invoke-SystemPendingRebootChecks {
    param(
        [Parameter(Mandatory)]
        $Context,
        [Parameter(Mandatory)]
        $Result
    )

    $artifact = Get-AnalyzerArtifact -Context $Context -Name 'pendingreboot'
    if (-not $artifact) {
        Add-CategoryIssue -CategoryResult $Result -Severity 'info' -Title 'Pending reboot inventory missing' -Subcategory 'Pending Reboot'
        return
    }

    $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $artifact)
    if (-not $payload) {
        Add-CategoryIssue -CategoryResult $Result -Severity 'info' -Title 'Pending reboot data unavailable' -Subcategory 'Pending Reboot'
        return
    }

    $indicatorEntries = @()
    if ($payload.PSObject.Properties['Indicators']) {
        $indicatorEntries = $payload.Indicators
        if (-not ($indicatorEntries -is [System.Collections.IEnumerable] -and -not ($indicatorEntries -is [string]))) {
            $indicatorEntries = @($indicatorEntries)
        }
    }

    $presentIndicators = @()
    foreach ($entry in $indicatorEntries) {
        if (-not $entry) { continue }
        $present = $false
        if ($entry.PSObject.Properties['Present']) {
            $present = [bool]$entry.Present
        }
        if ($present) {
            $presentIndicators += $entry
        }
    }

    $fileRenameEvidence = New-Object System.Collections.Generic.List[string]
    $fileRenameErrors = New-Object System.Collections.Generic.List[string]
    $pendingFileRenames = $false

    if ($payload.PSObject.Properties['PendingFileRenames']) {
        $renamePayload = $payload.PendingFileRenames
        $sets = @('PendingFileRenameOperations','PendingFileRenameOperations2')
        foreach ($name in $sets) {
            if (-not $renamePayload.PSObject.Properties[$name]) { continue }
            $values = $renamePayload.$name
            if (-not ($values -is [System.Collections.IEnumerable] -and -not ($values -is [string]))) {
                $values = @($values)
            }

            $index = 0
            foreach ($value in $values) {
                if ($null -eq $value) { continue }
                if ($value -is [string]) {
                    $trimmed = $value.Trim()
                    if ($trimmed) {
                        $pendingFileRenames = $true
                        if ($fileRenameEvidence.Count -lt 6) {
                            $fileRenameEvidence.Add(('{0}[{1}]: {2}' -f $name, $index, $trimmed)) | Out-Null
                        }
                    }
                } elseif ($value.PSObject.Properties['Error']) {
                    $err = [string]$value.Error
                    if ($err) { $fileRenameErrors.Add($err) | Out-Null }
                }
                $index++
            }
        }
    }

    $renameState = $null
    $nameMismatch = $false
    $tcpMismatch = $false
    if ($payload.PSObject.Properties['ComputerRenameState']) {
        $renameState = $payload.ComputerRenameState
        if ($renameState) {
            if ($renameState.PSObject.Properties['NameMismatch']) {
                $nameMismatch = [bool]$renameState.NameMismatch
            }
            if ($renameState.PSObject.Properties['TcpipMismatch']) {
                $tcpMismatch = [bool]$renameState.TcpipMismatch
            }
        }
    }

    if ($fileRenameErrors.Count -gt 0) {
        Add-CategoryIssue -CategoryResult $Result -Severity 'info' -Title 'Unable to enumerate pending file rename operations' -Evidence (($fileRenameErrors | Select-Object -First 5) -join "`n") -Subcategory 'Pending Reboot'
    }

    if (($presentIndicators.Count -eq 0) -and -not $pendingFileRenames -and -not $nameMismatch -and -not $tcpMismatch) {
        Add-CategoryNormal -CategoryResult $Result -Title 'No pending reboot indicators detected' -Subcategory 'Pending Reboot'
        return
    }

    if ($presentIndicators.Count -gt 0) {
        $evidenceLines = New-Object System.Collections.Generic.List[string]
        foreach ($entry in $presentIndicators) {
            $line = $entry.Name
            if ($entry.PSObject.Properties['Path'] -and $entry.Path) {
                $line = '{0} ({1})' -f $entry.Name, $entry.Path
            }
            $evidenceLines.Add($line) | Out-Null
        }
        Add-CategoryIssue -CategoryResult $Result -Severity 'medium' -Title 'Updates pending reboot' -Evidence (($evidenceLines | Select-Object -First 8) -join "`n") -Subcategory 'Pending Reboot'
    }

    if ($pendingFileRenames) {
        $evidence = $fileRenameEvidence
        if ($evidence.Count -eq 0) {
            $evidence = @('PendingFileRenameOperations contains entries.')
        }
        Add-CategoryIssue -CategoryResult $Result -Severity 'medium' -Title 'File rename operations require a reboot' -Evidence (($evidence | Select-Object -First 8) -join "`n") -Subcategory 'Pending Reboot'
    }

    if ($renameState -and ($nameMismatch -or $tcpMismatch)) {
        $details = New-Object System.Collections.Generic.List[string]
        if ($renameState.PSObject.Properties['ActiveName'] -and $renameState.ActiveName) {
            $details.Add("Active name: $($renameState.ActiveName)") | Out-Null
        }
        if ($renameState.PSObject.Properties['PendingName'] -and $renameState.PendingName) {
            $details.Add("Pending name: $($renameState.PendingName)") | Out-Null
        }
        if ($renameState.PSObject.Properties['TcpipHostname'] -and $renameState.TcpipHostname) {
            $details.Add("TCP/IP hostname: $($renameState.TcpipHostname)") | Out-Null
        }
        if ($renameState.PSObject.Properties['TcpipPendingName'] -and $renameState.TcpipPendingName) {
            $details.Add("TCP/IP pending hostname: $($renameState.TcpipPendingName)") | Out-Null
        }

        $title = if ($nameMismatch) { 'Computer rename pending reboot' } else { 'Hostname change pending reboot' }
        Add-CategoryIssue -CategoryResult $Result -Severity 'low' -Title $title -Evidence (($details | Where-Object { $_ }) -join "`n") -Subcategory 'Pending Reboot'
    }
}
