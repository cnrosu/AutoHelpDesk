function Format-HardwareBatteryRuntime {
    param([double]$Minutes)

    if ($null -eq $Minutes) { return $null }

    $timeSpan = [System.TimeSpan]::FromMinutes($Minutes)
    $parts = New-Object System.Collections.Generic.List[string]

    if ($timeSpan.Days -gt 0) { $parts.Add(("{0}d" -f $timeSpan.Days)) | Out-Null }
    if ($timeSpan.Hours -gt 0) { $parts.Add(("{0}h" -f $timeSpan.Hours)) | Out-Null }
    if ($timeSpan.Minutes -gt 0) { $parts.Add(("{0}m" -f $timeSpan.Minutes)) | Out-Null }

    if ($parts.Count -eq 0) {
        $parts.Add(("{0}m" -f [math]::Round($Minutes, 0))) | Out-Null
    }

    return $parts -join ' '
}

function Invoke-HardwareBatteryHeuristic {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Context,

        [Parameter(Mandatory)]
        $CategoryResult
    )

    $issueCount = 0
    $batteryArtifact = Get-AnalyzerArtifact -Context $Context -Name 'battery'
    Write-HeuristicDebug -Source 'Hardware/Battery' -Message 'Resolved battery artifact' -Data ([ordered]@{
        Found = [bool]$batteryArtifact
    })

    if (-not $batteryArtifact) {
        return [pscustomobject]@{ IssueCount = 0 }
    }

    $batteryPayload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $batteryArtifact)
    Write-HeuristicDebug -Source 'Hardware/Battery' -Message 'Resolved battery payload' -Data ([ordered]@{
        HasPayload = [bool]$batteryPayload
    })

    if (-not $batteryPayload) {
        return [pscustomobject]@{ IssueCount = 0 }
    }

    $batteryErrors = @()
    if ($batteryPayload.PSObject.Properties['Errors'] -and $batteryPayload.Errors) {
        $batteryErrors = @($batteryPayload.Errors | Where-Object { $_ })
    }

    $batteryEntries = @()
    if ($batteryPayload.PSObject.Properties['Batteries'] -and $batteryPayload.Batteries) {
        $batteryEntries = @($batteryPayload.Batteries | Where-Object { $_ })
    }

    $averageLife = $null
    if ($batteryPayload.PSObject.Properties['AverageLife']) {
        $averageLife = $batteryPayload.AverageLife
    }

    $lowWearThreshold    = 10.0
    $mediumWearThreshold = 20.0
    $highWearThreshold   = 30.0

    Write-HeuristicDebug -Source 'Hardware/Battery' -Message 'Parsed battery payload' -Data ([ordered]@{
        BatteryCount       = $batteryEntries.Count
        AverageLifeMinutes = if ($averageLife -and $averageLife.PSObject.Properties['AtFullChargeMinutes']) { $averageLife.AtFullChargeMinutes } else { $null }
        ErrorCount         = $batteryErrors.Count
    })

    if ($batteryErrors.Count -gt 0) {
        $firstError = $batteryErrors | Select-Object -First 1
        $errorText = if ($firstError -and $firstError.PSObject.Properties['Error'] -and $firstError.Error) { [string]$firstError.Error } else { 'Unknown error' }
        $source = if ($firstError -and $firstError.PSObject.Properties['Source'] -and $firstError.Source) { [string]$firstError.Source } else { 'root\\wmi battery classes' }
        Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'info' -Title 'Battery health query reported an error, so health data may be incomplete.' -Evidence ("{0}: {1}" -f $source, $errorText) -Subcategory 'Battery'
        $issueCount++
    }

    foreach ($battery in $batteryEntries) {
        if (-not $battery) { continue }

        $label = if ($battery.PSObject.Properties['Name'] -and $battery.Name) { [string]$battery.Name } else { 'Primary battery' }

        $design = $null
        if ($battery.PSObject.Properties['DesignCapacitymWh']) {
            $designValue = $battery.DesignCapacitymWh
            if ($designValue -ne $null -and $designValue -ne '') { $design = [double]$designValue }
        }

        $full = $null
        if ($battery.PSObject.Properties['FullChargeCapacitymWh']) {
            $fullValue = $battery.FullChargeCapacitymWh
            if ($fullValue -ne $null -and $fullValue -ne '') { $full = [double]$fullValue }
        }

        $remaining = $null
        if ($battery.PSObject.Properties['RemainingCapacitymWh']) {
            $remainingValue = $battery.RemainingCapacitymWh
            if ($remainingValue -ne $null -and $remainingValue -ne '') { $remaining = [double]$remainingValue }
        }

        $designmAh = $null
        if ($battery.PSObject.Properties['DesignCapacitymAh']) {
            $designmAhValue = $battery.DesignCapacitymAh
            if ($designmAhValue -ne $null -and $designmAhValue -ne '') { $designmAh = [double]$designmAhValue }
        }

        $fullmAh = $null
        if ($battery.PSObject.Properties['FullChargeCapacitymAh']) {
            $fullmAhValue = $battery.FullChargeCapacitymAh
            if ($fullmAhValue -ne $null -and $fullmAhValue -ne '') { $fullmAh = [double]$fullmAhValue }
        }

        $remainingmAh = $null
        if ($battery.PSObject.Properties['RemainingCapacitymAh']) {
            $remainingmAhValue = $battery.RemainingCapacitymAh
            if ($remainingmAhValue -ne $null -and $remainingmAhValue -ne '') { $remainingmAh = [double]$remainingmAhValue }
        }

        $cycleCount = $null
        if ($battery.PSObject.Properties['CycleCount']) {
            $cycleValue = $battery.CycleCount
            if ($cycleValue -ne $null -and $cycleValue -ne '') { $cycleCount = [int]$cycleValue }
        }

        $wearPct = $null
        if ($battery.PSObject.Properties['DegradationPercent'] -and $battery.DegradationPercent -ne $null -and $battery.DegradationPercent -ne '') {
            $wearPct = [double]$battery.DegradationPercent
        } elseif ($design -and $design -gt 0 -and $full -ne $null -and $full -ge 0) {
            $wearPct = [math]::Round((1 - ($full / $design)) * 100, 2)
        }

        if ($wearPct -ne $null) {
            if ($wearPct -lt 0) { $wearPct = 0 }
            if ($wearPct -gt 100) { $wearPct = 100 }
        }

        $charging = $null
        if ($battery.PSObject.Properties['Status_Charging']) {
            $charging = [bool]$battery.Status_Charging
        }

        $powerOnline = $null
        if ($battery.PSObject.Properties['Status_PowerOnline']) {
            $powerOnline = [bool]$battery.Status_PowerOnline
        }

        $impactSummaryParts = New-Object System.Collections.Generic.List[string]
        if ($fullmAh -ne $null) { $impactSummaryParts.Add(("Full≈{0:N0}mAh" -f $fullmAh)) | Out-Null }
        if ($remainingmAh -ne $null) { $impactSummaryParts.Add(("Now≈{0:N0}mAh" -f $remainingmAh)) | Out-Null }
        if ($design -ne $null) { $impactSummaryParts.Add(("Design={0:N0}mWh" -f $design)) | Out-Null }
        if ($wearPct -ne $null) { $impactSummaryParts.Add(("Degradation={0:N1}%" -f $wearPct)) | Out-Null }
        if ($charging -ne $null -and $charging) { $impactSummaryParts.Add('Charging') | Out-Null }

        $evidenceLines = New-Object System.Collections.Generic.List[string]
        if ($impactSummaryParts.Count -gt 0) {
            $evidenceLines.Add("Snapshot: {0}" -f ($impactSummaryParts.ToArray() -join ' · ')) | Out-Null
        }
        if ($design -ne $null) {
            $designSuffix = if ($designmAh -ne $null) { " (~{0:N0} mAh)" -f $designmAh } else { '' }
            $evidenceLines.Add(("Design capacity: {0:N0} mWh{1}" -f $design, $designSuffix)) | Out-Null
        }
        if ($full -ne $null) {
            $fullSuffix = if ($fullmAh -ne $null) { " (~{0:N0} mAh)" -f $fullmAh } else { '' }
            $evidenceLines.Add(("Full-charge capacity: {0:N0} mWh{1}" -f $full, $fullSuffix)) | Out-Null
        }
        if ($remaining -ne $null) {
            $remainingSuffix = if ($remainingmAh -ne $null) { " (~{0:N0} mAh)" -f $remainingmAh } else { '' }
            $evidenceLines.Add(("Remaining capacity: {0:N0} mWh{1}" -f $remaining, $remainingSuffix)) | Out-Null
        }
        if ($wearPct -ne $null) {
            $evidenceLines.Add(("Estimated wear: {0:N1}%" -f $wearPct)) | Out-Null
        }
        if ($cycleCount -ne $null) {
            $evidenceLines.Add(("Reported cycle count: {0}" -f $cycleCount)) | Out-Null
        }
        if ($battery.PSObject.Properties['AverageDischargeMilliwatts'] -and $battery.AverageDischargeMilliwatts) {
            $evidenceLines.Add(("Average discharge rate: {0:N0} mW" -f $battery.AverageDischargeMilliwatts)) | Out-Null
        }
        if ($charging -ne $null) {
            $evidenceLines.Add(("Charging: {0}" -f ([string]$charging))) | Out-Null
        }
        if ($powerOnline -ne $null) {
            $evidenceLines.Add(("Power source online: {0}" -f ([string]$powerOnline))) | Out-Null
        }

        if ($averageLife) {
            $lifeDisplay = $null
            if ($averageLife.PSObject.Properties['AtFullChargeMinutes'] -and $averageLife.AtFullChargeMinutes -ne $null) {
                $lifeDisplay = Format-HardwareBatteryRuntime -Minutes ([double]$averageLife.AtFullChargeMinutes)
            }
            if (-not $lifeDisplay -and $averageLife.PSObject.Properties['AtFullCharge'] -and $averageLife.AtFullCharge) {
                $lifeDisplay = [string]$averageLife.AtFullCharge
            }
            if ($lifeDisplay) {
                $evidenceLines.Add(("Average runtime (full charge): {0}" -f $lifeDisplay)) | Out-Null
            }
        }

        $evidence = if ($evidenceLines.Count -gt 0) { $evidenceLines.ToArray() -join "`n" } else { $null }

        $remediation = $null
        $title = $null
        $severity = 'info'

        if ($wearPct -eq $null) {
            if ($design -or $full) {
                $title = "Battery '{0}' reported incomplete capacity data, so unplugged runtime cannot be estimated." -f $label
                $remediation = 'Ensure the battery exposes design and full-charge capacity through WMI, or rerun diagnostics after a full charge/discharge cycle.'
                Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'info' -Title $title -Evidence $evidence -Subcategory 'Battery' -Remediation $remediation
                $issueCount++
            }
        } else {
            if     ($wearPct -ge $highWearThreshold)   { $severity = 'high' }
            elseif ($wearPct -ge $mediumWearThreshold) { $severity = 'medium' }
            elseif ($wearPct -ge $lowWearThreshold)    { $severity = 'low' }
            else                                       { $severity = 'info' }

            switch ($severity) {
                'high' {
                    $title = "Battery '{0}' has lost about {1:N1}% of its original capacity, so unplugged runtime will feel dramatically shorter." -f $label, $wearPct
                    $remediation = 'Battery wear is high. Consider calibrating with a full charge/discharge and plan for replacement if runtime is insufficient.'
                }
                'medium' {
                    $title = "Battery '{0}' has lost about {1:N1}% of its original capacity, so unplugged runtime will be noticeably shorter." -f $label, $wearPct
                    $remediation = 'Battery wear is moderate. Monitor runtime; calibration may help tighten the reported full-charge capacity.'
                }
                'low' {
                    $title = "Battery '{0}' shows about {1:N1}% wear, so unplugged runtime will be slightly shorter than new." -f $label, $wearPct
                    $remediation = 'Slight wear detected. No action is required beyond periodic rechecks.'
                }
                default {
                    $title = "Battery '{0}' is in good health, so unplugged runtime should match expectations." -f $label
                    $remediation = 'Battery health is good. No action required.'
                }
            }

            Add-CategoryIssue -CategoryResult $CategoryResult -Severity $severity -Title $title -Evidence $evidence -Subcategory 'Battery' -Remediation $remediation
            $issueCount++
        }

        if ($design -ne $null -and $full -ne $null) {
            $detailsParts = New-Object System.Collections.Generic.List[string]
            if ($cycleCount -ne $null) { $detailsParts.Add(("Cycle count: {0}" -f $cycleCount)) | Out-Null }
            if ($battery.PSObject.Properties['Chemistry'] -and $battery.Chemistry) { $detailsParts.Add(("Chemistry: {0}" -f $battery.Chemistry)) | Out-Null }
            if ($battery.PSObject.Properties['Manufacturer'] -and $battery.Manufacturer) { $detailsParts.Add(("Manufacturer: {0}" -f $battery.Manufacturer)) | Out-Null }

            $wearDisplay = if ($wearPct -ne $null) { " | Wear: {0:N1}%" -f $wearPct } else { '' }
            $details = if ($detailsParts.Count -gt 0) { $detailsParts.ToArray() -join '; ' } else { '' }
            $fullStatusSuffix = if ($fullmAh -ne $null) { " (~{0:N0} mAh)" -f $fullmAh } else { '' }
            $designStatusSuffix = if ($designmAh -ne $null) { " (~{0:N0} mAh)" -f $designmAh } else { '' }
            $status = "Full: {0:N0} mWh{1} | Design: {2:N0} mWh{3}{4}" -f $full, $fullStatusSuffix, $design, $designStatusSuffix, $wearDisplay
            Add-CategoryCheck -CategoryResult $CategoryResult -Name ("Battery {0} capacity" -f $label) -Status $status -Details $details
        }

        if ($averageLife) {
            $runtimeDisplay = $null
            if ($averageLife.PSObject.Properties['AtFullChargeMinutes'] -and $averageLife.AtFullChargeMinutes -ne $null) {
                $runtimeDisplay = Format-HardwareBatteryRuntime -Minutes ([double]$averageLife.AtFullChargeMinutes)
            }
            if (-not $runtimeDisplay -and $averageLife.PSObject.Properties['AtFullCharge'] -and $averageLife.AtFullCharge) {
                $runtimeDisplay = [string]$averageLife.AtFullCharge
            }

            if ($runtimeDisplay) {
                $details = if ($averageLife.PSObject.Properties['Period'] -and $averageLife.Period) { "Period: $($averageLife.Period)" } else { '' }
                Add-CategoryCheck -CategoryResult $CategoryResult -Name ("Battery {0} average runtime" -f $label) -Status $runtimeDisplay -Details $details
            }
        }
    }

    return [pscustomobject]@{ IssueCount = $issueCount }
}
