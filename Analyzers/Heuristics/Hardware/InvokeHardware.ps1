function Invoke-HardwareHeuristics {
    param(
        [Parameter(Mandatory)]
        $Context
    )

    Write-HeuristicDebug -Source 'Hardware' -Message 'Starting hardware heuristics' -Data ([ordered]@{
        ArtifactCount = if ($Context -and $Context.Artifacts) { $Context.Artifacts.Count } else { 0 }
    })

    $result = New-CategoryResult -Name 'Hardware'
    $issueCount = 0

    $formatBatteryRuntime = {
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

    $batteryArtifact = Get-AnalyzerArtifact -Context $Context -Name 'battery'
    Write-HeuristicDebug -Source 'Hardware/Battery' -Message 'Resolved battery artifact' -Data ([ordered]@{
        Found = [bool]$batteryArtifact
    })

    if ($batteryArtifact) {
        $batteryPayload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $batteryArtifact)
        Write-HeuristicDebug -Source 'Hardware/Battery' -Message 'Resolved battery payload' -Data ([ordered]@{
            HasPayload = [bool]$batteryPayload
        })

        if ($batteryPayload) {
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

            Write-HeuristicDebug -Source 'Hardware/Battery' -Message 'Parsed battery payload' -Data ([ordered]@{
                BatteryCount       = $batteryEntries.Count
                AverageLifeMinutes = if ($averageLife -and $averageLife.PSObject.Properties['AtFullChargeMinutes']) { $averageLife.AtFullChargeMinutes } else { $null }
                ErrorCount         = $batteryErrors.Count
            })

            if ($batteryErrors.Count -gt 0) {
                $firstError = $batteryErrors | Select-Object -First 1
                $errorText = if ($firstError -and $firstError.PSObject.Properties['Error'] -and $firstError.Error) { [string]$firstError.Error } else { 'Unknown error' }
                $source = if ($firstError -and $firstError.PSObject.Properties['Source'] -and $firstError.Source) { [string]$firstError.Source } else { 'powercfg.exe /batteryreport' }
                Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Battery report command reported an error, so health data may be incomplete.' -Evidence ("{0}: {1}" -f $source, $errorText) -Subcategory 'Battery'
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

                $cycleCount = $null
                if ($battery.PSObject.Properties['CycleCount']) {
                    $cycleValue = $battery.CycleCount
                    if ($cycleValue -ne $null -and $cycleValue -ne '') { $cycleCount = [int]$cycleValue }
                }

                $capacityPct = $null
                if ($design -and $design -gt 0 -and $full -ne $null -and $full -ge 0) {
                    $capacityPct = [math]::Round(($full / $design) * 100, 1)
                }

                $wearPct = if ($capacityPct -ne $null) { [math]::Round(100 - $capacityPct, 1) } else { $null }
                if ($wearPct -ne $null -and $wearPct -lt 0) { $wearPct = 0 }

                $evidenceLines = New-Object System.Collections.Generic.List[string]
                if ($design -ne $null) { $evidenceLines.Add(("Design capacity: {0:N0} mWh" -f $design)) | Out-Null }
                if ($full -ne $null) { $evidenceLines.Add(("Full charge capacity: {0:N0} mWh" -f $full)) | Out-Null }
                if ($wearPct -ne $null) { $evidenceLines.Add(("Estimated wear: {0:N1}% loss" -f $wearPct)) | Out-Null }
                if ($cycleCount -ne $null) { $evidenceLines.Add(("Reported cycle count: {0}" -f $cycleCount)) | Out-Null }

                if ($averageLife) {
                    $lifeDisplay = $null
                    if ($averageLife.PSObject.Properties['AtFullChargeMinutes'] -and $averageLife.AtFullChargeMinutes -ne $null) {
                        $lifeDisplay = & $formatBatteryRuntime ([double]$averageLife.AtFullChargeMinutes)
                    }
                    if (-not $lifeDisplay -and $averageLife.PSObject.Properties['AtFullCharge'] -and $averageLife.AtFullCharge) {
                        $lifeDisplay = [string]$averageLife.AtFullCharge
                    }
                    if ($lifeDisplay) {
                        $evidenceLines.Add(("Average runtime (full charge): {0}" -f $lifeDisplay)) | Out-Null
                    }
                }

                $evidence = if ($evidenceLines.Count -gt 0) { $evidenceLines.ToArray() -join "`n" } else { $null }

                if ($capacityPct -eq $null) {
                    if ($design -or $full) {
                        $title = "Battery {0} reported incomplete capacity data, so degradation cannot be calculated." -f $label
                        Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title $title -Evidence $evidence -Subcategory 'Battery'
                        $issueCount++
                    }
                } elseif ($capacityPct -lt 60) {
                    $title = "Battery '{0}' holds {1}% of its original charge capacity, so unplugged runtime will feel dramatically shorter." -f $label, $capacityPct
                    Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title $title -Evidence $evidence -Subcategory 'Battery'
                    $issueCount++
                } elseif ($capacityPct -lt 80) {
                    $title = "Battery '{0}' holds {1}% of its original charge capacity, so unplugged runtime will be noticeably shorter." -f $label, $capacityPct
                    Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title $title -Evidence $evidence -Subcategory 'Battery'
                    $issueCount++
                } else {
                    $title = "Battery '{0}' retains {1}% of its original charge capacity, so runtime remains close to new." -f $label, $capacityPct
                    Add-CategoryNormal -CategoryResult $result -Title $title -Evidence $evidence -Subcategory 'Battery'
                }

                if ($design -ne $null -and $full -ne $null) {
                    $detailsParts = New-Object System.Collections.Generic.List[string]
                    if ($cycleCount -ne $null) { $detailsParts.Add(("Cycle count: {0}" -f $cycleCount)) | Out-Null }
                    if ($battery.PSObject.Properties['Chemistry'] -and $battery.Chemistry) { $detailsParts.Add(("Chemistry: {0}" -f $battery.Chemistry)) | Out-Null }
                    if ($battery.PSObject.Properties['Manufacturer'] -and $battery.Manufacturer) { $detailsParts.Add(("Manufacturer: {0}" -f $battery.Manufacturer)) | Out-Null }

                    $details = if ($detailsParts.Count -gt 0) { $detailsParts.ToArray() -join '; ' } else { '' }
                    $status = "Full: {0:N0} mWh | Design: {1:N0} mWh" -f $full, $design
                    Add-CategoryCheck -CategoryResult $result -Name ("Battery {0} capacity" -f $label) -Status $status -Details $details
                }

                if ($averageLife) {
                    $runtimeDisplay = $null
                    if ($averageLife.PSObject.Properties['AtFullChargeMinutes'] -and $averageLife.AtFullChargeMinutes -ne $null) {
                        $runtimeDisplay = & $formatBatteryRuntime ([double]$averageLife.AtFullChargeMinutes)
                    }
                    if (-not $runtimeDisplay -and $averageLife.PSObject.Properties['AtFullCharge'] -and $averageLife.AtFullCharge) {
                        $runtimeDisplay = [string]$averageLife.AtFullCharge
                    }

                    if ($runtimeDisplay) {
                        $details = if ($averageLife.PSObject.Properties['Period'] -and $averageLife.Period) { "Period: $($averageLife.Period)" } else { '' }
                        Add-CategoryCheck -CategoryResult $result -Name ("Battery {0} average runtime" -f $label) -Status $runtimeDisplay -Details $details
                    }
                }
            }
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
        $serviceNameRaw = Get-DriverPropertyValue -Entry $entry -Names @('Service Name','Driver Name','Module Name')
        $isBluetooth = $false
        foreach ($candidate in @($classRaw, $label, $descriptionRaw, $serviceNameRaw)) {
            if (-not $candidate) { continue }
            if (Test-BluetoothIndicator -Value $candidate) {
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

    $pnpEntries = @()
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
            $instanceId = Get-DriverPropertyValue -Entry $entry -Names @('Instance ID','InstanceId','Device Instance ID')
            $isBluetoothDevice = $false
            foreach ($candidate in @($className, $label, $description, $instanceId)) {
                if (-not $candidate) { continue }
                if (Test-BluetoothIndicator -Value $candidate) {
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
        DriverEntriesTotal    = $entries.Count
        DriverEntriesMatched  = $bluetoothDrivers.Count
        ProblemEntriesTotal   = $pnpEntries.Count
        ProblemEntriesMatched = $bluetoothProblemDevices.Count
    })

    $bluetoothDetected = ($bluetoothDrivers.Count -gt 0) -or ($bluetoothProblemDevices.Count -gt 0)
    if (-not $bluetoothDetected) {
        $evidenceLines = @()
        $evidenceLines += "Driver inventory entries scanned: $($entries.Count)"
        $evidenceLines += "Bluetooth indicators matched in drivers: $($bluetoothDrivers.Count)"
        $evidenceLines += "Problem devices parsed: $($pnpEntries.Count)"
        $evidenceLines += "Bluetooth indicators matched in problem devices: $($bluetoothProblemDevices.Count)"
        $evidenceLines += "Indicators checked: 'bluetooth', drivers starting with BTH*/IBT*/QCBT*/BTATH*"
        Add-CategoryIssue -CategoryResult $result -Severity 'warning' -Title 'Bluetooth adapter not detected, so wireless accessories cannot pair.' -Evidence ($evidenceLines -join "`n") -Subcategory 'Bluetooth'
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
