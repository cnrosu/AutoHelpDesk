function Invoke-SystemPendingRebootChecks {
    param(
        [Parameter(Mandatory)]
        $Context,
        [Parameter(Mandatory)]
        $Result
    )

    Write-HeuristicDebug -Source 'System/PendingReboot' -Message 'Starting pending reboot checks'

    $artifact = Get-AnalyzerArtifact -Context $Context -Name 'pendingreboot'
    Write-HeuristicDebug -Source 'System/PendingReboot' -Message 'Resolved pendingreboot artifact' -Data ([ordered]@{ Found = [bool]$artifact })

    if (-not $artifact) {
        Add-CategoryIssue -CategoryResult $Result -Severity 'warning' -Title 'Pending reboot inventory missing, so a reboot requirement may be hidden and updates could remain blocked.' -Subcategory 'Pending Reboot'
        return
    }

    $entry = $artifact
    if ($artifact -is [System.Collections.IEnumerable] -and -not ($artifact -is [string])) {
        $entry = ($artifact | Select-Object -First 1)
    }

    if (-not $entry -or -not $entry.Data) {
        Add-CategoryIssue -CategoryResult $Result -Severity 'warning' -Title 'Pending reboot data unavailable, so a reboot requirement may be hidden and updates could remain blocked.' -Subcategory 'Pending Reboot'
        return
    }

    $data = $entry.Data
    if ($data.PSObject.Properties['Error'] -and $data.Error) {
        Add-CategoryIssue -CategoryResult $Result -Severity 'warning' -Title 'Pending reboot data unavailable, so a reboot requirement may be hidden and updates could remain blocked.' -Evidence $data.Error -Subcategory 'Pending Reboot'
        return
    }

    if (-not $data.PSObject.Properties['Signals']) {
        Add-CategoryIssue -CategoryResult $Result -Severity 'warning' -Title 'Pending reboot data missing signals, so a reboot requirement may be hidden and updates could remain blocked.' -Subcategory 'Pending Reboot'
        return
    }

    $errors = @()
    if ($data.PSObject.Properties['Errors']) {
        $rawErrors = $data.Errors
        if ($rawErrors -and -not ($rawErrors -is [System.Collections.IEnumerable] -and -not ($rawErrors -is [string]))) {
            $rawErrors = @($rawErrors)
        }
        if ($rawErrors) {
            $errors = @($rawErrors | Where-Object { $_ })
        }
    }

    if ($errors.Count -gt 0) {
        Add-CategoryIssue -CategoryResult $Result -Severity 'info' -Title 'Pending reboot signals incomplete due to registry access errors, so a reboot requirement may be hidden.' -Evidence (($errors | Select-Object -First 5) -join "`n") -Subcategory 'Pending Reboot'
        return
    }

    $signals = $data.Signals
    $counts = if ($data.PSObject.Properties['Counts']) { $data.Counts } else { $null }

    function ConvertTo-Bool {
        param($Value)

        if ($Value -is [bool]) { return $Value }
        if ($Value -is [int] -or $Value -is [long]) { return $Value -ne 0 }
        if ($Value -is [string]) {
            $normalized = $Value.Trim().ToLowerInvariant()
            if (-not $normalized) { return $false }
            return @('true', '1', 'yes', 'y') -contains $normalized
        }
        if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
            foreach ($item in $Value) {
                if (ConvertTo-Bool -Value $item) { return $true }
            }
            return $false
        }

        return [bool]$Value
    }

    function Get-SignalValue {
        param(
            [Parameter(Mandatory)]
            [string]$Name
        )

        if (-not $signals) { return $false }
        if ($signals.PSObject.Properties[$Name]) {
            return ConvertTo-Bool -Value $signals.PSObject.Properties[$Name].Value
        }
        return $false
    }

    $cbsRebootPending = Get-SignalValue -Name 'CBS.RebootPending'
    $cbsSessionsPending = Get-SignalValue -Name 'CBS.SessionsPending'
    $wuRebootRequired = Get-SignalValue -Name 'WU.RebootRequired'
    $msiInProgress = Get-SignalValue -Name 'MSI.InProgress'
    $pfroHasEntries = Get-SignalValue -Name 'PFRO.HasEntries'
    $renamePending = Get-SignalValue -Name 'RenamePending'

    $pfroSample = @()
    if ($data.PSObject.Properties['PFRO.Sample']) {
        $pfroSampleRaw = $data.'PFRO.Sample'
        if ($pfroSampleRaw -and -not ($pfroSampleRaw -is [System.Collections.IEnumerable] -and -not ($pfroSampleRaw -is [string]))) {
            $pfroSampleRaw = @($pfroSampleRaw)
        }
        if ($pfroSampleRaw) {
            $pfroSample = @($pfroSampleRaw | Where-Object { $_ } | Select-Object -First 5 | ForEach-Object { [string]$_ })
        }
    }

    $pfroTotal = 0
    if ($counts -and $counts.PSObject.Properties['PFRO.Total']) {
        $value = $counts.'PFRO.Total'
        if ($value -is [int] -or $value -is [long]) {
            $pfroTotal = [int]$value
        } elseif ($value -is [string]) {
            [int]::TryParse($value, [ref]$pfroTotal) | Out-Null
        }
    } elseif ($pfroHasEntries -and $pfroSample.Count -gt 0) {
        $pfroTotal = $pfroSample.Count
    }

    $collectedAt = if ($data.PSObject.Properties['CollectedAtUtc']) { [string]$data.CollectedAtUtc } else { $null }
    $renameDetails = if ($data.PSObject.Properties['RenameDetails']) { $data.RenameDetails } else { $null }

    if (-not $cbsRebootPending -and -not $cbsSessionsPending -and -not $wuRebootRequired -and -not $msiInProgress -and -not $pfroHasEntries -and -not $renamePending) {
        Add-CategoryNormal -CategoryResult $Result -Title 'No pending reboot indicators detected' -Subcategory 'Pending Reboot'
        return
    }

    $highSeverity = $cbsRebootPending -or $cbsSessionsPending -or $wuRebootRequired
    $pfroLikelyLow = $false
    if ($pfroHasEntries -and -not $highSeverity -and -not $msiInProgress -and -not $renamePending) {
        if ($pfroTotal -le 2 -and $pfroSample.Count -gt 0) {
            $pfroLikelyLow = $true
            foreach ($item in $pfroSample) {
                $upper = $item.ToUpperInvariant()
                if ($upper -like 'C:\WINDOWS*' -or $upper -like 'C:\PROGRAM FILES*' -or $upper -like 'C:\PROGRAMDATA*') {
                    $pfroLikelyLow = $false
                    break
                }
            }
        }
    }

    $severity = 'medium'
    if ($highSeverity) {
        $severity = 'high'
    } elseif ($renamePending -and -not $pfroHasEntries -and -not $msiInProgress) {
        $severity = 'low'
    } elseif ($pfroLikelyLow) {
        $severity = 'low'
    }

    $title = 'System/Pending Reboot: Pending operations require restart'
    if ($severity -eq 'high') {
        if ($wuRebootRequired -and ($cbsRebootPending -or $cbsSessionsPending)) {
            $title = 'System/Pending Reboot: Windows servicing requires restart (CBS/WU)'
        } elseif ($wuRebootRequired) {
            $title = 'System/Pending Reboot: Windows Update requires restart'
        } else {
            $title = 'System/Pending Reboot: Windows servicing requires restart (CBS)'
        }
    } elseif ($pfroHasEntries -and -not $msiInProgress -and -not $renamePending) {
        $titlePrefix = if ($severity -eq 'low') { 'System/Pending Reboot: Minor file rename operations pending' } else { 'System/Pending Reboot: File rename operations pending' }
        $title = '{0} (PFRO: {1} {2})' -f $titlePrefix, $pfroTotal, $(if ($pfroTotal -eq 1) { 'item' } else { 'items' })
    } elseif ($msiInProgress -and -not $pfroHasEntries -and -not $renamePending) {
        $title = 'System/Pending Reboot: MSI installer pending restart'
    } elseif ($renamePending -and -not $pfroHasEntries -and -not $msiInProgress) {
        $title = 'System/Pending Reboot: Computer rename pending'
    }

    $highTriggerNames = @()
    if ($cbsRebootPending) { $highTriggerNames += 'CBS.RebootPending' }
    if ($cbsSessionsPending) { $highTriggerNames += 'CBS.SessionsPending' }
    if ($wuRebootRequired) { $highTriggerNames += 'WU.RebootRequired' }

    $additionalTriggers = [System.Collections.Generic.List[string]]::new()
    if ($pfroHasEntries) {
        $additionalTriggers.Add(('PFRO {0} {1}' -f $pfroTotal, $(if ($pfroTotal -eq 1) { 'item' } else { 'items' }))) | Out-Null
    }
    if ($msiInProgress) { $additionalTriggers.Add('MSI in-progress') | Out-Null }
    if ($renamePending) { $additionalTriggers.Add('Rename pending') | Out-Null }
    $additionalTriggerTexts = @($additionalTriggers.ToArray())

    $summary = $null
    if ($highSeverity) {
        $primary = if ($highTriggerNames.Count -gt 0) { $highTriggerNames -join '/' } else { 'servicing signals' }
        $summary = 'Reboot required due to {0}.' -f $primary
        if ($additionalTriggerTexts.Count -gt 0) {
            $summary += ' Additional pending operations detected: {0}.' -f ($additionalTriggerTexts -join ', ')
        }
    } elseif ($msiInProgress -and -not $pfroHasEntries -and -not $renamePending) {
        $summary = 'Reboot required to complete an MSI installation (Installer\InProgress present).'
    } elseif ($pfroHasEntries -and -not $renamePending -and -not $msiInProgress) {
        $summary = 'Reboot required to complete PendingFileRenameOperations ({0}).' -f ($additionalTriggerTexts -join ', ')
    } elseif ($renamePending -and -not $pfroHasEntries -and -not $msiInProgress) {
        $summary = 'Computer rename pending until the next restart completes.'
    } else {
        if ($additionalTriggerTexts.Count -gt 0) {
            $summary = 'Reboot required to clear pending operations: {0}.' -f ($additionalTriggerTexts -join ', ')
        } else {
            $summary = 'Reboot required to clear pending operations.'
        }
    }

    $signalOrder = @('CBS.RebootPending', 'CBS.SessionsPending', 'WU.RebootRequired', 'MSI.InProgress', 'PFRO.HasEntries', 'RenamePending')
    $signalsMap = [ordered]@{}
    foreach ($name in $signalOrder) {
        $signalsMap[$name] = Get-SignalValue -Name $name
    }

    $countsMap = [ordered]@{
        'PFRO.Total' = $pfroTotal
    }

    $triggerSummary = [ordered]@{
        High  = @($highTriggerNames | Where-Object { $_ })
        Other = @($additionalTriggerTexts | Where-Object { $_ })
    }

    $evidencePayload = [ordered]@{
        Triggers = $triggerSummary
        Signals  = $signalsMap
        Counts   = $countsMap
    }

    if ($pfroSample.Count -gt 0) {
        $displayTotal = if ($pfroTotal -gt 0) { $pfroTotal } else { $pfroSample.Count }
        $evidencePayload['PFROSample'] = [ordered]@{
            Count        = $pfroSample.Count
            DisplayTotal = $displayTotal
            Entries      = @($pfroSample)
        }
    }

    if ($renamePending -and $renameDetails) {
        $renameEvidence = [ordered]@{}
        $active = if ($renameDetails.PSObject.Properties['ActiveName']) { [string]$renameDetails.ActiveName } else { $null }
        $pending = if ($renameDetails.PSObject.Properties['PendingName']) { [string]$renameDetails.PendingName } else { $null }
        if ($active -or $pending) {
            $renameEvidence['ComputerName'] = [ordered]@{
                Active  = if ($active) { $active } else { '(unknown)' }
                Pending = if ($pending) { $pending } else { '(unknown)' }
            }
        }
        $tcpActive = if ($renameDetails.PSObject.Properties['TcpipHostname']) { [string]$renameDetails.TcpipHostname } else { $null }
        $tcpPending = if ($renameDetails.PSObject.Properties['TcpipPendingName']) { [string]$renameDetails.TcpipPendingName } else { $null }
        if ($tcpActive -or $tcpPending) {
            $renameEvidence['TcpipHostname'] = [ordered]@{
                Current = if ($tcpActive) { $tcpActive } else { '(unknown)' }
                Pending = if ($tcpPending) { $tcpPending } else { '(unknown)' }
            }
        }

        if ($renameEvidence.Count -gt 0) {
            $evidencePayload['RenameDetails'] = $renameEvidence
        }
    }

    if ($collectedAt) {
        $evidencePayload['CollectedAtUtc'] = $collectedAt
    }

    $evidenceLines = @(
        'Pending reboot evidence (JSON):',
        ($evidencePayload | ConvertTo-Json -Depth 6)
    )

    $remediationSteps = [System.Collections.Generic.List[string]]::new()
    $remediationSteps.Add('Restart the device at the next maintenance window to complete servicing/updates.') | Out-Null
    if ($highSeverity) {
        $remediationSteps.Add('If reboot prompts persist, complete the Windows Update cycle (install → reboot → re-check).') | Out-Null
    }
    if ($msiInProgress) {
        $remediationSteps.Add('Finish or cancel any in-progress MSI installers so Installer\InProgress clears.') | Out-Null
    }
    if ($pfroHasEntries) {
        $remediationSteps.Add('Investigate frequent PendingFileRenameOperations entries (fonts, ClickToRun, drivers) and repair or reinstall affected apps.') | Out-Null
    }
    if ($renamePending) {
        $remediationSteps.Add('For rename scenarios, confirm device rename policies complete after restart.') | Out-Null
    }

    $remediationText = $null
    $uniqueRemediationSteps = $remediationSteps | Select-Object -Unique
    if ($uniqueRemediationSteps.Count -gt 0) {
        $remediationText = ($uniqueRemediationSteps | ForEach-Object { '- {0}' -f $_ }) -join "`n"
    }

    $issueParams = @{
        CategoryResult = $Result
        Severity       = $severity
        Title          = $title
        Evidence       = $evidenceLines
        Subcategory    = 'Pending Reboot'
    }

    if ($summary) { $issueParams['Explanation'] = $summary.Trim() }
    if ($remediationText) { $issueParams['Remediation'] = $remediationText }

    Add-CategoryIssue @issueParams
}
