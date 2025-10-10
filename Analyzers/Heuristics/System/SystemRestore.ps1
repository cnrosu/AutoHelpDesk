function Invoke-SystemRestoreChecks {
    param(
        [Parameter(Mandatory)]
        $Context,
        [Parameter(Mandatory)]
        $Result
    )

    $source = 'System/SystemRestore'
    Write-HeuristicDebug -Source $source -Message 'Starting System Restore checks'

    $artifact = Get-AnalyzerArtifact -Context $Context -Name 'systemrestore'
    Write-HeuristicDebug -Source $source -Message 'Resolved systemrestore artifact' -Data ([ordered]@{
        Found = [bool]$artifact
    })

    $subcategory = 'System Restore'

    if (-not $artifact) {
        Add-CategoryIssue -CategoryResult $Result -Severity 'info' -Title 'System Restore inventory missing, so recovery status cannot be verified when troubleshooting rollbacks.' -Subcategory $subcategory
        return
    }

    $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $artifact)
    Write-HeuristicDebug -Source $source -Message 'Evaluating systemrestore payload' -Data ([ordered]@{
        HasPayload = [bool]$payload
    })

    if (-not $payload) {
        Add-CategoryIssue -CategoryResult $Result -Severity 'info' -Title 'System Restore data unavailable, so recovery status cannot be verified when troubleshooting rollbacks.' -Subcategory $subcategory
        return
    }

    $config = $null
    $configError = $null
    $configSource = 'SystemRestore registry'
    if ($payload.PSObject.Properties['RegistryConfig']) {
        $candidate = $payload.RegistryConfig
        if ($candidate -and $candidate.PSObject.Properties['Error'] -and $candidate.Error) {
            $configError = [string]$candidate.Error
            if ($candidate.PSObject.Properties['Source'] -and $candidate.Source) {
                $configSource = [string]$candidate.Source
            }
        } else {
            $config = $candidate
        }
    }

    if ($configError) {
        Add-CategoryIssue -CategoryResult $Result -Severity 'info' -Title 'System Restore registry configuration unavailable, so protection status cannot be confirmed before troubleshooting rollbacks.' -Evidence ("${configSource}: $configError") -Subcategory $subcategory
    }

    $driveConfigs = @()
    $driveErrors = New-Object System.Collections.Generic.List[string]
    if ($payload.PSObject.Properties['DriveConfigurations']) {
        $rawDriveConfigs = $payload.DriveConfigurations
        if ($rawDriveConfigs -is [System.Collections.IEnumerable] -and -not ($rawDriveConfigs -is [string])) {
            foreach ($entry in $rawDriveConfigs) {
                if (-not $entry) { continue }
                if ($entry.PSObject.Properties['Error'] -and $entry.Error) {
                    $label = if ($entry.PSObject.Properties['Drive'] -and $entry.Drive) { [string]$entry.Drive } elseif ($entry.PSObject.Properties['Source'] -and $entry.Source) { [string]$entry.Source } else { 'Drive configuration' }
                    $driveErrors.Add(("{0}: {1}" -f $label, $entry.Error)) | Out-Null
                    continue
                }
                $driveConfigs += ,$entry
            }
        } elseif ($rawDriveConfigs) {
            if ($rawDriveConfigs.PSObject.Properties['Error'] -and $rawDriveConfigs.Error) {
                $label = if ($rawDriveConfigs.PSObject.Properties['Source'] -and $rawDriveConfigs.Source) { [string]$rawDriveConfigs.Source } else { 'Drive configuration' }
                $driveErrors.Add(("{0}: {1}" -f $label, $rawDriveConfigs.Error)) | Out-Null
            } else {
                $driveConfigs += ,$rawDriveConfigs
            }
        }
    }

    if ($driveErrors.Count -gt 0) {
        Add-CategoryIssue -CategoryResult $Result -Severity 'info' -Title 'System Restore drive settings unavailable, so per-volume protection status cannot be confirmed before troubleshooting rollbacks.' -Evidence (($driveErrors | Select-Object -First 5) -join "`n") -Subcategory $subcategory
    }

    $restorePoints = @()
    $restorePointError = $null
    $restorePointSource = 'SystemRestore'
    if ($payload.PSObject.Properties['RestorePoints']) {
        $rawRestorePoints = $payload.RestorePoints
        if ($rawRestorePoints -is [System.Collections.IEnumerable] -and -not ($rawRestorePoints -is [string])) {
            foreach ($entry in $rawRestorePoints) {
                if (-not $entry) { continue }
                if ($entry.PSObject.Properties['Error'] -and $entry.Error) {
                    $restorePointError = [string]$entry.Error
                    if ($entry.PSObject.Properties['Source'] -and $entry.Source) {
                        $restorePointSource = [string]$entry.Source
                    }
                    break
                }
                $restorePoints += ,$entry
            }
        } elseif ($rawRestorePoints) {
            if ($rawRestorePoints.PSObject.Properties['Error'] -and $rawRestorePoints.Error) {
                $restorePointError = [string]$rawRestorePoints.Error
                if ($rawRestorePoints.PSObject.Properties['Source'] -and $rawRestorePoints.Source) {
                    $restorePointSource = [string]$rawRestorePoints.Source
                }
            } else {
                $restorePoints += ,$rawRestorePoints
            }
        }
    }

    if ($restorePointError) {
        Add-CategoryIssue -CategoryResult $Result -Severity 'info' -Title 'System Restore points could not be enumerated, so available rollbacks may be hidden during troubleshooting.' -Evidence ("${restorePointSource}: $restorePointError") -Subcategory $subcategory
    }

    $globalDisabled = $false
    $globalDisableKnown = $false
    if ($config -and $config.PSObject.Properties['DisableSR']) {
        $globalDisableKnown = $true
        try {
            $globalDisabled = ([int64]$config.DisableSR -ne 0)
        } catch {
            $globalDisabled = $true
        }
    }

    $driveConfigured = $false
    $driveEnabledCount = 0
    $driveDisabledCount = 0
    foreach ($drive in $driveConfigs) {
        if (-not $drive) { continue }
        $driveConfigured = $true
        if ($drive.PSObject.Properties['DisableSR']) {
            try {
                if ([int64]$drive.DisableSR -ne 0) {
                    $driveDisabledCount++
                } else {
                    $driveEnabledCount++
                }
            } catch {
                $driveDisabledCount++
            }
        } else {
            $driveEnabledCount++
        }
    }

    $allDrivesDisabled = $driveConfigured -and ($driveDisabledCount -gt 0) -and ($driveEnabledCount -eq 0)

    if ($globalDisableKnown -and $globalDisabled) {
        $evidence = New-Object System.Collections.Generic.List[string]
        if ($config.PSObject.Properties['DisableSR']) {
            $evidence.Add(("DisableSR={0}" -f $config.DisableSR)) | Out-Null
        }
        if ($config.PSObject.Properties['DisableConfig']) {
            $evidence.Add(("DisableConfig={0}" -f $config.DisableConfig)) | Out-Null
        }
        Add-CategoryIssue -CategoryResult $Result -Severity 'high' -Title 'System Restore disabled, so rollbacks are unavailable when updates or drivers fail.' -Evidence (($evidence | Where-Object { $_ }) | Select-Object -First 5) -Subcategory $subcategory
        return
    }

    if ($allDrivesDisabled) {
        $evidence = foreach ($drive in ($driveConfigs | Select-Object -First 5)) {
            if (-not $drive) { continue }
            $flag = if ($drive.PSObject.Properties['DisableSR']) { [string]$drive.DisableSR } else { 'unknown' }
            if ($drive.PSObject.Properties['Drive'] -and $drive.Drive) {
                "{0}: DisableSR={1}" -f $drive.Drive, $flag
            } else {
                "DisableSR={0}" -f $flag
            }
        }
        Add-CategoryIssue -CategoryResult $Result -Severity 'high' -Title 'System Restore disabled on every monitored drive, so rollbacks are unavailable when updates or drivers fail.' -Evidence ($evidence | Where-Object { $_ }) -Subcategory $subcategory
        return
    }

    $restorePointCount = if ($restorePoints) { $restorePoints.Count } else { 0 }
    $likelyEnabled = $false
    if ($restorePointCount -gt 0) {
        $likelyEnabled = $true
    }
    if (-not $likelyEnabled -and $globalDisableKnown -and -not $globalDisabled) {
        $likelyEnabled = $true
    }
    if (-not $likelyEnabled -and $driveEnabledCount -gt 0) {
        $likelyEnabled = $true
    }

    if ($restorePointCount -gt 0) {
        $evidenceLines = New-Object System.Collections.Generic.List[string]
        $culture = [System.Globalization.CultureInfo]::InvariantCulture
        $style = [System.Globalization.DateTimeStyles]::RoundtripKind

        $sorted = @($restorePoints | Sort-Object -Property @{ Expression = {
            if ($_.PSObject.Properties['CreationTime'] -and $_.CreationTime) {
                try {
                    return [datetime]::Parse($_.CreationTime, $culture, $style)
                } catch {
                    return Get-Date '1900-01-01'
                }
            }
            return Get-Date '1900-01-01'
        }; Descending = $true })

        $latestRestorePointTimestamp = $null
        if ($sorted.Count -gt 0) {
            $candidate = $sorted[0]
            if ($candidate.PSObject.Properties['CreationTime'] -and $candidate.CreationTime) {
                try {
                    $latestRestorePointTimestamp = [datetime]::Parse($candidate.CreationTime, $culture, $style)
                } catch {
                    $latestRestorePointTimestamp = $null
                }
            }
        }

        foreach ($point in $sorted | Select-Object -First 5) {
            if (-not $point) { continue }
            $timestamp = $null
            if ($point.PSObject.Properties['CreationTime'] -and $point.CreationTime) {
                try {
                    $timestamp = [datetime]::Parse($point.CreationTime, $culture, $style).ToString('yyyy-MM-dd HH:mm')
                } catch {
                    $timestamp = [string]$point.CreationTime
                }
            }
            $description = if ($point.PSObject.Properties['Description'] -and $point.Description) { [string]$point.Description } else { 'No description' }
            $typeName = if ($point.PSObject.Properties['RestorePointTypeName'] -and $point.RestorePointTypeName) { [string]$point.RestorePointTypeName } elseif ($point.PSObject.Properties['RestorePointType']) { 'Type {0}' -f $point.RestorePointType } else { $null }
            $line = if ($timestamp) { "$timestamp - $description" } else { $description }
            if ($typeName) { $line = "$line ($typeName)" }
            $evidenceLines.Add($line) | Out-Null
        }

        $title = if ($restorePointCount -eq 1) {
            'System Restore enabled with 1 restore point available.'
        } else {
            "System Restore enabled with $restorePointCount restore points available."
        }

        $evidenceText = ($evidenceLines | Where-Object { $_ }) -join "`n"
        if ([string]::IsNullOrWhiteSpace($evidenceText)) {
            $evidenceText = $null
        }

        if ($latestRestorePointTimestamp) {
            $threshold = (Get-Date).AddDays(-30)
            if ($latestRestorePointTimestamp -lt $threshold) {
                $evidenceDetails = if ($evidenceText) { $evidenceText } else { $null }
                $freshnessEvidence = New-Object System.Collections.Generic.List[string]
                $freshnessEvidence.Add(("Most recent restore point: {0}" -f $latestRestorePointTimestamp.ToString('yyyy-MM-dd HH:mm'))) | Out-Null
                if ($evidenceDetails) {
                    $freshnessEvidence.Add($evidenceDetails) | Out-Null
                }
                Add-CategoryIssue -CategoryResult $Result -Severity 'warning' -Title 'System Restore lacks recent restore points, so you cannot roll back to last month''s changes.' -Evidence (($freshnessEvidence | Where-Object { $_ }) -join "`n") -Subcategory $subcategory
                return
            }
        }

        Add-CategoryNormal -CategoryResult $Result -Title $title -Evidence $evidenceText -Subcategory $subcategory
        return
    }

    if ($likelyEnabled -and -not $restorePointError) {
        Add-CategoryIssue -CategoryResult $Result -Severity 'medium' -Title 'System Restore has no restore points, so you cannot roll back to recover from recent changes.' -Subcategory $subcategory
        return
    }

    if (-not $config -and -not $driveConfigured -and $restorePointCount -eq 0 -and -not $restorePointError) {
        Add-CategoryIssue -CategoryResult $Result -Severity 'info' -Title 'System Restore status could not be determined, so rollbacks might be unavailable when recovering from issues.' -Subcategory $subcategory
    }
}
