function ConvertTo-HardwareAutorunInt {
    param($Value)

    if ($null -eq $Value) { return $null }

    if ($Value -is [int] -or $Value -is [long]) { return [int]$Value }
    if ($Value -is [uint32] -or $Value -is [uint64]) { return [int]$Value }

    if ($Value -is [string]) {
        $text = $Value.Trim()
        if (-not $text) { return $null }

        if ($text -match '^0x([0-9a-f]+)$') {
            try { return [Convert]::ToInt32($matches[1], 16) } catch { return $null }
        }

        $parsed = 0
        if ([int]::TryParse($text, [ref]$parsed)) { return $parsed }

        $decimalMatch = [regex]::Match($text, '([0-9]+)')
        if ($decimalMatch.Success) {
            try { return [int]$decimalMatch.Groups[1].Value } catch { return $null }
        }
    }

    return $null
}

function Get-HardwareAutorunEntry {
    param(
        $Entries,
        [string]$Path
    )

    if (-not $Entries -or -not $Path) { return $null }

    $normalizedTarget = $Path.TrimEnd('\').ToLowerInvariant()

    foreach ($entry in $Entries) {
        if (-not $entry) { continue }
        if (-not $entry.Path) { continue }
        $entryPath = $entry.Path.TrimEnd('\').ToLowerInvariant()
        if ($entryPath -eq $normalizedTarget) { return $entry }
    }

    return $null
}

function Get-HardwareAutorunValue {
    param(
        $Entry,
        [string]$Name
    )

    if (-not $Entry -or -not $Name) { return $null }
    if (-not $Entry.Values) { return $null }

    $property = $Entry.Values.PSObject.Properties[$Name]
    if (-not $property) { return $null }

    return $property.Value
}

function Format-HardwareAutorunValue {
    param($Value)

    if ($null -eq $Value) { return 'missing' }

    $intValue = ConvertTo-HardwareAutorunInt $Value
    if ($null -ne $intValue) {
        return ('0x{0:X2} ({1})' -f ($intValue -band 0xFF), $intValue)
    }

    return [string]$Value
}

function Format-HardwareAutorunEntry {
    param(
        [string]$Label,
        $Entry
    )

    $noDriveType = Format-HardwareAutorunValue (Get-HardwareAutorunValue -Entry $Entry -Name 'NoDriveTypeAutoRun')
    $noAutoRun = Format-HardwareAutorunValue (Get-HardwareAutorunValue -Entry $Entry -Name 'NoAutoRun')
    $noDriveAuto = Format-HardwareAutorunValue (Get-HardwareAutorunValue -Entry $Entry -Name 'NoDriveAutoRun')

    $parts = [System.Collections.Generic.List[string]]::new()
    $parts.Add("NoDriveTypeAutoRun=$noDriveType") | Out-Null
    $parts.Add("NoAutoRun=$noAutoRun") | Out-Null
    $parts.Add("NoDriveAutoRun=$noDriveAuto") | Out-Null

    return ('{0}: {1}' -f $Label, ($parts.ToArray() -join '; '))
}

function Invoke-HardwareHeuristics {
    param(
        [Parameter(Mandatory)]
        $Context
    )

    Write-HeuristicDebug -Source 'Hardware' -Message 'Starting hardware heuristics' -Data ([ordered]@{
        ArtifactCount = if ($Context -and $Context.Artifacts) { $Context.Artifacts.Count } else { 0 }
    })

    $result = New-CategoryResult -Name 'Hardware'

    $autorunArtifact = Get-AnalyzerArtifact -Context $Context -Name 'autorun'
    Write-HeuristicDebug -Source 'Hardware' -Message 'Resolved autorun artifact' -Data ([ordered]@{
        Found = [bool]$autorunArtifact
    })

    $autorunEntries = @()
    if ($autorunArtifact) {
        $autorunPayload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $autorunArtifact)
        $autorunEntries = @()
        if ($autorunPayload -and $autorunPayload.Registry) {
            if ($autorunPayload.Registry -is [System.Collections.IEnumerable] -and -not ($autorunPayload.Registry -is [string])) {
                foreach ($item in $autorunPayload.Registry) { $autorunEntries += ,$item }
            } else {
                $autorunEntries = @($autorunPayload.Registry)
            }
        }

        Write-HeuristicDebug -Source 'Hardware' -Message 'Evaluating autorun payload' -Data ([ordered]@{
            HasRegistry = ($autorunEntries.Count -gt 0)
        })
    }

    if (-not $autorunArtifact) {
        Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Autorun/Autoplay artifact missing, so removable media autorun posture is unknown.' -Subcategory 'Removable Media'
    } elseif ($autorunEntries.Count -eq 0) {
        Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Autorun/Autoplay registry data unavailable, so removable media autorun posture is unknown.' -Subcategory 'Removable Media'
    } else {
        $machinePolicyEntry = Get-HardwareAutorunEntry -Entries $autorunEntries -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer'
        $machineLegacyEntry = Get-HardwareAutorunEntry -Entries $autorunEntries -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
        $userPolicyEntry = Get-HardwareAutorunEntry -Entries $autorunEntries -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer'
        $userLegacyEntry = Get-HardwareAutorunEntry -Entries $autorunEntries -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'

        $machineNoDrive = $null
        $machineNoDriveSource = $null
        foreach ($entry in @($machinePolicyEntry, $machineLegacyEntry)) {
            if (-not $entry) { continue }
            $value = ConvertTo-HardwareAutorunInt (Get-HardwareAutorunValue -Entry $entry -Name 'NoDriveTypeAutoRun')
            if ($null -ne $value) {
                $machineNoDrive = $value
                $machineNoDriveSource = $entry.Path
                break
            }
        }

        $machineNoAutoRun = $null
        $machineNoAutoSource = $null
        foreach ($entry in @($machinePolicyEntry, $machineLegacyEntry)) {
            if (-not $entry) { continue }
            $value = ConvertTo-HardwareAutorunInt (Get-HardwareAutorunValue -Entry $entry -Name 'NoAutoRun')
            if ($null -ne $value) {
                $machineNoAutoRun = $value
                $machineNoAutoSource = $entry.Path
                break
            }
        }

        $userNoDrive = $null
        foreach ($entry in @($userPolicyEntry, $userLegacyEntry)) {
            if (-not $entry) { continue }
            $value = ConvertTo-HardwareAutorunInt (Get-HardwareAutorunValue -Entry $entry -Name 'NoDriveTypeAutoRun')
            if ($null -ne $value) { $userNoDrive = $value; break }
        }

        $userNoAutoRun = $null
        foreach ($entry in @($userPolicyEntry, $userLegacyEntry)) {
            if (-not $entry) { continue }
            $value = ConvertTo-HardwareAutorunInt (Get-HardwareAutorunValue -Entry $entry -Name 'NoAutoRun')
            if ($null -ne $value) { $userNoAutoRun = $value; break }
        }

        $expectedNoDriveType = 0xFF
        $expectedNoAutoRun = 1

        $machineHardened = ($machineNoDrive -eq $expectedNoDriveType) -and ($machineNoAutoRun -eq $expectedNoAutoRun)
        $userOverridesPresent = ($null -ne $userNoDrive) -or ($null -ne $userNoAutoRun)
        $userHardened = $true
        if ($userOverridesPresent) {
            $userHardened = ($userNoDrive -eq $expectedNoDriveType) -and ($userNoAutoRun -eq $expectedNoAutoRun)
        }

        $evidenceLines = [System.Collections.Generic.List[string]]::new()
        $evidenceLines.Add(Format-HardwareAutorunEntry -Label 'HKLM Policies\\Explorer' -Entry $machinePolicyEntry) | Out-Null
        $evidenceLines.Add(Format-HardwareAutorunEntry -Label 'HKLM\\...\\Policies\\Explorer' -Entry $machineLegacyEntry) | Out-Null
        $evidenceLines.Add(Format-HardwareAutorunEntry -Label 'HKCU Policies\\Explorer' -Entry $userPolicyEntry) | Out-Null
        $evidenceLines.Add(Format-HardwareAutorunEntry -Label 'HKCU\\...\\Policies\\Explorer' -Entry $userLegacyEntry) | Out-Null

        $evidence = $evidenceLines.ToArray() -join "`n"

        Write-HeuristicDebug -Source 'Hardware' -Message 'Autorun hardening evaluated' -Data ([ordered]@{
            MachineNoDrive      = $machineNoDrive
            MachineNoDrivePath  = $machineNoDriveSource
            MachineNoAutoRun    = $machineNoAutoRun
            MachineNoAutoPath   = $machineNoAutoSource
            UserNoDrive         = $userNoDrive
            UserNoAutoRun       = $userNoAutoRun
            MachineHardened     = $machineHardened
            UserOverrides       = $userOverridesPresent
            UserHardened        = $userHardened
        })

        if (-not $machineHardened -or -not $userHardened) {
            $title = 'Autorun/Autoplay remains enabled because NoDriveTypeAutoRun/NoAutoRun are not set to hardened values (0xFF/1), allowing removable media to auto-execute.'
            Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title $title -Evidence $evidence -Subcategory 'Removable Media'
        } else {
            $title = 'Autorun/Autoplay disabled via NoDriveTypeAutoRun = 0xFF and NoAutoRun = 1.'
            Add-CategoryNormal -CategoryResult $result -Title $title -Evidence $evidence -Subcategory 'Removable Media'
        }
    }

    $driversArtifact = Get-AnalyzerArtifact -Context $Context -Name 'drivers'
    Write-HeuristicDebug -Source 'Hardware' -Message 'Resolved driver artifact' -Data ([ordered]@{
        Found = [bool]$driversArtifact
    })

    if (-not $driversArtifact) {
        Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title "Driver inventory artifact missing, so Device Manager issues can't be evaluated." -Subcategory 'Collection'
        return $result
    }

    $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $driversArtifact)
    Write-HeuristicDebug -Source 'Hardware' -Message 'Resolved driver payload' -Data ([ordered]@{
        HasPayload = [bool]$payload
    })

    if (-not $payload) {
        Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title "Driver inventory payload missing, so Device Manager issues can't be evaluated." -Subcategory 'Collection'
        return $result
    }

    if ($payload.DriverQuery -and $payload.DriverQuery.PSObject.Properties['Error'] -and $payload.DriverQuery.Error) {
        $source = if ($payload.DriverQuery.PSObject.Properties['Source']) { [string]$payload.DriverQuery.Source } else { 'driverquery.exe' }
        $evidence = if ($payload.DriverQuery.Error) { [string]$payload.DriverQuery.Error } else { 'Unknown error' }
        Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title "Driver inventory command failed, so Device Manager issues may be hidden." -Evidence ("{0}: {1}" -f $source, $evidence) -Subcategory 'Collection'
        return $result
    }

    if ($payload.PnpProblems -and $payload.PnpProblems.PSObject.Properties['Error'] -and $payload.PnpProblems.Error) {
        $source = if ($payload.PnpProblems.PSObject.Properties['Source']) { [string]$payload.PnpProblems.Source } else { 'pnputil.exe' }
        $evidence = if ($payload.PnpProblems.Error) { [string]$payload.PnpProblems.Error } else { 'Unknown error' }
        Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title "Problem device inventory command failed, so Device Manager issues may be hidden." -Evidence ("{0}: {1}" -f $source, $evidence) -Subcategory 'Collection'
    }

    $driverText = ConvertTo-HardwareDriverText -Value $payload.DriverQuery
    Write-HeuristicDebug -Source 'Hardware' -Message 'Driver query text resolved' -Data ([ordered]@{
        HasText = [bool]$driverText
        Length  = if ($driverText) { $driverText.Length } else { 0 }
    })

    if (-not $driverText) {
        Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title "Driver inventory empty, so Device Manager issues can't be evaluated." -Subcategory 'Collection'
        return $result
    }

    $entries = Parse-DriverQueryEntries -Text $driverText
    Write-HeuristicDebug -Source 'Hardware' -Message 'Parsed driver inventory entries' -Data ([ordered]@{
        EntryCount = $entries.Count
    })

    if ($entries.Count -eq 0) {
        Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title "Driver inventory could not be parsed, so Device Manager issues may be hidden." -Subcategory 'Collection'
        return $result
    }

    $failureEventMap = Get-DriverFailureEventMap -Context $Context
    Write-HeuristicDebug -Source 'Hardware' -Message 'Loaded driver failure event map' -Data ([ordered]@{
        HasEvents = ($failureEventMap -and ($failureEventMap.Count -gt 0))
        Keys      = if ($failureEventMap) { $failureEventMap.Count } else { 0 }
    })

    $issueCount = 0
    foreach ($entry in $entries) {
        if (-not $entry) { continue }

        $label = Get-DriverLabel -Entry $entry
        $statusRaw = Get-DriverPropertyValue -Entry $entry -Names @('Status')
        $statusNormalized = Normalize-DriverStatus -Value $statusRaw
        if ($statusNormalized -and $statusNormalized -ne 'ok' -and $statusNormalized -ne 'unknown') {
            $severity = switch ($statusNormalized) {
                'error'    { 'high' }
                'degraded' { 'medium' }
                default    { 'info' }
            }
            $title = if ($statusRaw) {
                "Driver status '{0}' reported for {1}, so the device may malfunction." -f $statusRaw, $label
            } else {
                "Driver status indicates an issue for {0}, so the device may malfunction." -f $label
            }
            Add-CategoryIssue -CategoryResult $result -Severity $severity -Title $title -Evidence (Get-DriverEvidence -Entry $entry) -Subcategory 'Device Manager'
            $issueCount++
        }

        $stateRaw = Get-DriverPropertyValue -Entry $entry -Names @('State')
        $startModeRaw = Get-DriverPropertyValue -Entry $entry -Names @('Start Mode','StartMode')
        $stateNormalized = Normalize-DriverState -Value $stateRaw
        $startModeNormalized = Normalize-DriverStartMode -Value $startModeRaw
        $driverTypeRaw = Get-DriverPropertyValue -Entry $entry -Names @('Driver Type','Type','Service Type')
        $driverTypeNormalized = Normalize-DriverType -Value $driverTypeRaw
        $shouldFlagStartIssue = $false
        $failureEvents = @()

        if ($startModeNormalized -in @('boot','system','auto') -and $stateNormalized -ne 'running' -and $stateNormalized -ne 'pending') {
            if ($startModeNormalized -eq 'auto') {
                $shouldFlagStartIssue = $true
            } elseif ($startModeNormalized -in @('boot','system')) {
                if ($driverTypeNormalized -eq 'kernel') {
                    $candidates = Get-DriverNameCandidates -Entry $entry
                    $failureEvents = Find-DriverFailureEvents -Candidates $candidates -Map $failureEventMap
                    if ($failureEvents -and $failureEvents.Count -gt 0) {
                        $shouldFlagStartIssue = $true
                    } else {
                        Write-HeuristicDebug -Source 'Hardware' -Message 'Skipping stopped boot/system kernel driver without corroborating events' -Data ([ordered]@{
                            Driver     = $label
                            StartMode  = $startModeRaw
                            State      = $stateRaw
                            DriverType = $driverTypeRaw
                        })
                    }
                } else {
                    $shouldFlagStartIssue = $true
                }
            }
        }

        if ($shouldFlagStartIssue) {
            $severity = if ($startModeNormalized -in @('boot','system')) { 'high' } else { 'medium' }
            $errorControlRaw = Get-DriverPropertyValue -Entry $entry -Names @('Error Control','ErrorControl')
            $errorControlNormalized = Normalize-DriverErrorControl -Value $errorControlRaw
            if ($errorControlNormalized -eq 'critical') { $severity = 'critical' }

            $title = if ($stateRaw -and $startModeRaw) {
                "Driver {0} is {1} despite start mode {2}, so hardware may not initialize." -f $label, $stateRaw, $startModeRaw
            } elseif ($startModeRaw) {
                "Driver {0} is not running despite start mode {1}, so hardware may not initialize." -f $label, $startModeRaw
            } else {
                "Driver {0} is not running despite an automatic start mode, so hardware may not initialize." -f $label
            }

            $evidenceParts = New-Object System.Collections.Generic.List[string]
            $driverEvidence = Get-DriverEvidence -Entry $entry
            if ($driverEvidence) { $evidenceParts.Add($driverEvidence) | Out-Null }

            if ($failureEvents -and $failureEvents.Count -gt 0) {
                $eventEvidence = Format-DriverFailureEvidence -Events $failureEvents
                if ($eventEvidence) {
                    $evidenceParts.Add("Related events:`n$eventEvidence") | Out-Null
                }
            }

            $evidence = if ($evidenceParts.Count -gt 0) { $evidenceParts.ToArray() -join "`n`n" } else { $null }

            Add-CategoryIssue -CategoryResult $result -Severity $severity -Title $title -Evidence $evidence -Subcategory 'Device Manager'
            $issueCount++
        }
    }

    $pnpText = ConvertTo-HardwareDriverText -Value $payload.PnpProblems
    Write-HeuristicDebug -Source 'Hardware' -Message 'Problem device text resolved' -Data ([ordered]@{
        HasText = [bool]$pnpText
        Length  = if ($pnpText) { $pnpText.Length } else { 0 }
    })

    if ($pnpText) {
        $pnpEntries = Parse-DriverQueryEntries -Text $pnpText
        Write-HeuristicDebug -Source 'Hardware' -Message 'Parsed problem device entries' -Data ([ordered]@{
            EntryCount = $pnpEntries.Count
        })

        foreach ($entry in $pnpEntries) {
            if (-not $entry) { continue }

            $label = Get-PnpDeviceLabel -Entry $entry
            $statusRaw = Get-DriverPropertyValue -Entry $entry -Names @('Status','Problem Status')
            $problemRaw = Get-DriverPropertyValue -Entry $entry -Names @('Problem','Problem Code','ProblemStatus')
            $normalized = Normalize-PnpProblem -Values @($statusRaw, $problemRaw)

            if ($normalized -eq 'missing-driver') {
                $title = "Device {0} is missing drivers (Code 28), so functionality may be limited." -f $label
                Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title $title -Evidence (Get-PnpDeviceEvidence -Entry $entry) -Subcategory 'Device Manager'
                $issueCount++
                continue
            }

            if ($normalized -eq 'problem') {
                $title = "Device Manager reports a problem for {0}." -f $label
                Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title $title -Evidence (Get-PnpDeviceEvidence -Entry $entry) -Subcategory 'Device Manager'
                $issueCount++
            }
        }
    }

    Write-HeuristicDebug -Source 'Hardware' -Message 'Device Manager analysis completed' -Data ([ordered]@{
        IssuesRaised = $issueCount
    })

    if ($issueCount -eq 0) {
        Add-CategoryNormal -CategoryResult $result -Title 'Device Manager reports all drivers healthy.' -Subcategory 'Device Manager'
    }

    return $result
}
