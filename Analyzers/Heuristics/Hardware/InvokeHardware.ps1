function Invoke-HardwareHeuristics {
    param(
        [Parameter(Mandatory)]
        $Context
    )

    Write-HeuristicDebug -Source 'Hardware' -Message 'Starting hardware heuristics' -Data ([ordered]@{
        ArtifactCount = if ($Context -and $Context.Artifacts) { $Context.Artifacts.Count } else { 0 }
    })

    $result = New-CategoryResult -Name 'Hardware'

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

    $inventory = Get-NormalizedDriverInventory -Payload $payload -VerboseLogging
    $entries = if ($inventory -and $inventory.Rows) { $inventory.Rows } else { @() }

    Write-HeuristicDebug -Source 'Hardware' -Message 'Resolved driver inventory' -Data ([ordered]@{
        RowCount = $entries.Count
        Source   = if ($inventory) { $inventory.Source } else { $null }
    })

    if ($entries.Count -eq 0) {
        Write-HeuristicDebug -Source 'Hardware' -Message 'Driver inventory parsing diagnostics' -Data ([ordered]@{
            AvailableProperties = if ($inventory -and $inventory.AvailableProperties -and $inventory.AvailableProperties.Count -gt 0) { $inventory.AvailableProperties -join ', ' } else { $null }
            TextPreview         = if ($inventory -and $inventory.TextPreview) { $inventory.TextPreview } else { $null }
        })
        $hasRawDriverData = $inventory -and ($inventory.HasDriverQueryData -or $inventory.HasTextPayload)
        $title = if ($hasRawDriverData) {
            "Driver inventory could not be parsed, so Device Manager issues may be hidden."
        } else {
            "Driver inventory empty, so Device Manager issues can't be evaluated."
        }
        Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title $title -Subcategory 'Collection'
        return $result
    }

    $failureEventMap = Get-DriverFailureEventMap -Context $Context
    Write-HeuristicDebug -Source 'Hardware' -Message 'Loaded driver failure event map' -Data ([ordered]@{
        HasEvents = ($failureEventMap -and ($failureEventMap.Count -gt 0))
        Keys      = if ($failureEventMap) { $failureEventMap.Count } else { 0 }
    })

    $bluetoothDrivers = New-Object System.Collections.Generic.List[pscustomobject]
    $bluetoothProblemDevices = New-Object System.Collections.Generic.List[pscustomobject]

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

        $classRaw = Get-DriverPropertyValue -Entry $entry -Names @('Class Name','ClassName','Class')
        $descriptionRaw = Get-DriverPropertyValue -Entry $entry -Names @('Device Description','Description')
        $isBluetooth = $false
        foreach ($candidate in @($classRaw, $label, $descriptionRaw)) {
            if (-not $candidate) { continue }
            if ($candidate -match '(?i)bluetooth') {
                $isBluetooth = $true
                break
            }
        }
        if ($isBluetooth) {
            $bluetoothDrivers.Add([pscustomobject]@{
                Entry               = $entry
                Label               = $label
                StatusRaw           = $statusRaw
                StatusNormalized    = $statusNormalized
                StateRaw            = $stateRaw
                StateNormalized     = $stateNormalized
                StartModeRaw        = $startModeRaw
                StartModeNormalized = $startModeNormalized
            }) | Out-Null
        }

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

            $className = Get-DriverPropertyValue -Entry $entry -Names @('Class Name','ClassName','Class')
            $description = Get-DriverPropertyValue -Entry $entry -Names @('Device Description','Friendly Name','Name')
            $isBluetoothDevice = $false
            foreach ($candidate in @($className, $label, $description)) {
                if (-not $candidate) { continue }
                if ($candidate -match '(?i)bluetooth') {
                    $isBluetoothDevice = $true
                    break
                }
            }
            if ($isBluetoothDevice) {
                $bluetoothProblemDevices.Add([pscustomobject]@{
                    Entry      = $entry
                    Label      = $label
                    Problem    = $normalized
                    StatusRaw  = $statusRaw
                    ProblemRaw = $problemRaw
                }) | Out-Null
            }

            if ($normalized -eq 'missing-driver') {
                if ($isBluetoothDevice) { continue }
                $title = "Device {0} is missing drivers (Code 28), so functionality may be limited." -f $label
                Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title $title -Evidence (Get-PnpDeviceEvidence -Entry $entry) -Subcategory 'Device Manager'
                $issueCount++
                continue
            }

            if ($normalized -eq 'problem') {
                if ($isBluetoothDevice) { continue }
                $title = "Device Manager reports a problem for {0}." -f $label
                Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title $title -Evidence (Get-PnpDeviceEvidence -Entry $entry) -Subcategory 'Device Manager'
                $issueCount++
            }
        }
    }

    Write-HeuristicDebug -Source 'Hardware' -Message 'Bluetooth device detection summary' -Data ([ordered]@{
        DriverEntries  = $bluetoothDrivers.Count
        ProblemEntries = $bluetoothProblemDevices.Count
    })

    $bluetoothDetected = ($bluetoothDrivers.Count -gt 0) -or ($bluetoothProblemDevices.Count -gt 0)
    if (-not $bluetoothDetected) {
        Add-CategoryIssue -CategoryResult $result -Severity 'warning' -Title 'Bluetooth adapter not detected, so wireless accessories cannot pair.' -Subcategory 'Bluetooth'
        $issueCount++
    } else {
        $bluetoothIssueEvidence = New-Object System.Collections.Generic.List[string]
        $bluetoothIssueFound = $false

        foreach ($record in $bluetoothDrivers) {
            $shouldFlagBluetooth = $false

            if ($record.StatusNormalized -in @('error','degraded')) {
                $shouldFlagBluetooth = $true
            } elseif ($record.StartModeNormalized -in @('boot','system','auto') -and $record.StateNormalized -notin @('running','pending')) {
                $shouldFlagBluetooth = $true
            }

            if ($shouldFlagBluetooth) {
                $bluetoothIssueFound = $true
                $driverEvidence = Get-DriverEvidence -Entry $record.Entry
                if ($driverEvidence) { $bluetoothIssueEvidence.Add($driverEvidence) | Out-Null }
            }
        }

        foreach ($device in $bluetoothProblemDevices) {
            if ($device.Problem -in @('missing-driver','problem')) {
                $bluetoothIssueFound = $true
                $pnpEvidence = Get-PnpDeviceEvidence -Entry $device.Entry
                if ($pnpEvidence) { $bluetoothIssueEvidence.Add($pnpEvidence) | Out-Null }
            }
        }

        if ($bluetoothIssueFound) {
            $evidence = if ($bluetoothIssueEvidence.Count -gt 0) { $bluetoothIssueEvidence.ToArray() } else { $null }
            Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Bluetooth adapter detected but not working, so wireless accessories cannot pair.' -Evidence $evidence -Subcategory 'Bluetooth'
            $issueCount++
        } else {
            Add-CategoryNormal -CategoryResult $result -Title 'Bluetooth adapter detected and appears to be working normally.' -Subcategory 'Bluetooth'
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
